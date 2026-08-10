<?php

declare(strict_types=1);

/**
 * Stateless, HMAC-signed two-step delete confirmation tokens.
 *
 * Every destructive tool (delete_message, empty_folder, delete_folder,
 * delete_contact, delete_identity) is called twice by design:
 *
 *   1. Without `confirm: true` - the tool does nothing destructive. It looks
 *      up and returns a human-readable preview of exactly what would be
 *      deleted, plus a `confirmation_token` that is cryptographically bound
 *      to this operation name, these exact target ids, and this exact agent.
 *   2. With `confirm: true` and that `confirmation_token` echoed back - the
 *      tool verifies the token (signature, expiry, operation, ids, agent)
 *      and only then performs the delete.
 *
 * No database row is needed to track "used" tokens: a token that is replayed
 * after a successful delete simply fails to find anything left to delete
 * (IMAP UIDs and addressbook record ids are not reused within the short
 * confirmation TTL), so replay has no destructive effect beyond the first
 * use. This keeps the mechanism self-contained and works with any MCP
 * client, without relying on client-side "elicitation" support.
 */
final class mcpcube_confirmation
{
    private static function hmac_key(): string
    {
        // Domain-separated from the credential-encryption key so a leaked
        // confirmation token can never be used to derive anything about
        // encrypted IMAP passwords, and vice versa.
        return hash_hmac('sha256', 'mcpcube-confirmation-key-v1', mcpcube_crypto::config_key(), true);
    }

    /** @param list<string> $ids */
    public static function issue(string $op, array $ids, string $agentTokenHash): string
    {
        $ttl = max(30, (int) rcmail::get_instance()->config->get('mcpcube_confirmation_ttl', 300));
        $payload = [
            'op' => $op,
            'ids' => self::normalize_ids($ids),
            'agent' => $agentTokenHash,
            'exp' => time() + $ttl,
        ];
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new RuntimeException('Could not encode confirmation token payload');
        }
        $encoded = rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
        $signature = hash_hmac('sha256', $encoded, self::hmac_key());

        return $encoded . '.' . $signature;
    }

    /** @param list<string> $ids */
    public static function verify(?string $token, string $op, array $ids, string $agentTokenHash): bool
    {
        if (!is_string($token) || $token === '' || !str_contains($token, '.')) {
            return false;
        }

        [$encoded, $signature] = explode('.', $token, 2);
        $expected = hash_hmac('sha256', $encoded, self::hmac_key());
        if (!hash_equals($expected, $signature)) {
            return false;
        }

        $json = base64_decode(strtr($encoded, '-_', '+/'), true);
        if ($json === false) {
            return false;
        }

        $payload = json_decode($json, true);
        if (!is_array($payload) || !isset($payload['op'], $payload['ids'], $payload['agent'], $payload['exp'])) {
            return false;
        }

        return $payload['op'] === $op
            && is_int($payload['exp']) && $payload['exp'] >= time()
            && is_string($payload['agent']) && hash_equals($agentTokenHash, $payload['agent'])
            && is_array($payload['ids']) && $payload['ids'] === self::normalize_ids($ids);
    }

    /** @param list<string> $ids @return list<string> */
    private static function normalize_ids(array $ids): array
    {
        $ids = array_map('strval', $ids);
        sort($ids, SORT_STRING);
        return array_values($ids);
    }
}

/**
 * A minimal JSON-RPC 2.0 / MCP tool-call dispatcher, run over the
 * "Streamable HTTP" transport in its simplest, fully spec-compliant mode:
 * every POST gets exactly one `application/json` response body and no
 * server-sent events, session IDs, or resumption. This is deliberate - every
 * MCPcube tool call is synchronous and independent (auth is a bearer token
 * re-checked on each request, see mcpcube_auth_context), so there is nothing
 * that needs a long-lived streaming session in v1.
 */
final class mcpcube_mcp_server
{
    public const PROTOCOL_VERSION = '2025-11-25';
    public const SUPPORTED_PROTOCOL_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26'];

    /** @var array<string, array{description: string, inputSchema: array, scope: ?string, handler: callable}> */
    private array $tools = [];

    /**
     * @param array<string, mixed> $inputSchema JSON Schema for the tool's arguments
     * @param string|null $scope required scope, or null if every authorized agent may call it
     * @param callable(array<string,mixed> $arguments, mcpcube_auth_context $ctx): array $handler
     *        must return an array with a `content` list per the MCP tool-result shape;
     *        may throw mcpcube_tool_error for a structured, isError:true result.
     */
    public function register_tool(string $name, string $description, array $inputSchema, ?string $scope, callable $handler): void
    {
        $this->tools[$name] = [
            'description' => $description,
            'inputSchema' => $inputSchema,
            'scope' => $scope,
            'handler' => $handler,
        ];
    }

    /**
     * @param array<string, mixed> $request decoded JSON-RPC request
     * @return array<string, mixed>|null decoded JSON-RPC response, or null for a notification (no reply expected)
     */
    public function handle(array $request, mcpcube_auth_context $ctx): ?array
    {
        $id = array_key_exists('id', $request) ? $request['id'] : null;
        $isNotification = !array_key_exists('id', $request);
        $method = $request['method'] ?? null;
        $params = is_array($request['params'] ?? null) ? $request['params'] : [];

        if (($request['jsonrpc'] ?? null) !== '2.0'
            || (array_key_exists('id', $request) && !is_int($id) && !is_string($id) && $id !== null)
            || !is_string($method)
        ) {
            return $isNotification ? null : self::error($id, -32600, 'Invalid Request');
        }

        try {
            $result = match ($method) {
                'initialize' => $this->handle_initialize($params),
                'notifications/initialized' => null,
                'ping' => new stdClass(),
                'tools/list' => $this->handle_tools_list(),
                'tools/call' => $this->handle_tools_call($params, $ctx),
                default => throw new mcpcube_rpc_error(-32601, "Method not found: {$method}"),
            };
        } catch (mcpcube_rpc_error $e) {
            return $isNotification ? null : self::error($id, $e->getCode(), $e->getMessage());
        }

        if ($isNotification || $method === 'notifications/initialized') {
            return null;
        }

        return [
            'jsonrpc' => '2.0',
            'id' => $id,
            'result' => $result,
        ];
    }

    /** @return array<string, mixed> */
    private function handle_initialize(array $params): array
    {
        $rcmail = rcmail::get_instance();
        $requested = is_string($params['protocolVersion'] ?? null) ? $params['protocolVersion'] : '';
        $version = in_array($requested, self::SUPPORTED_PROTOCOL_VERSIONS, true)
            ? $requested
            : self::PROTOCOL_VERSION;

        return [
            'protocolVersion' => $version,
            'capabilities' => ['tools' => new stdClass()],
            'serverInfo' => [
                'name' => (string) $rcmail->config->get('mcpcube_server_name', 'MCPcube'),
                'version' => '1.1.0',
            ],
        ];
    }

    /** @return array<string, mixed> */
    private function handle_tools_list(): array
    {
        $tools = [];
        foreach ($this->tools as $name => $tool) {
            $tools[] = [
                'name' => $name,
                'description' => $tool['description'],
                'inputSchema' => $tool['inputSchema'],
            ];
        }

        return ['tools' => $tools];
    }

    /**
     * @param array<string, mixed> $params
     * @return array<string, mixed>
     */
    private function handle_tools_call(array $params, mcpcube_auth_context $ctx): array
    {
        $name = $params['name'] ?? null;
        $arguments = is_array($params['arguments'] ?? null) ? $params['arguments'] : [];

        if (!is_string($name) || !isset($this->tools[$name])) {
            throw new mcpcube_rpc_error(-32602, 'Unknown tool: ' . (is_string($name) ? $name : json_encode($name)));
        }

        $tool = $this->tools[$name];

        if ($tool['scope'] !== null && !$ctx->has_scope($tool['scope'])) {
            return self::tool_error("This agent was not granted the '{$tool['scope']}' scope. Ask the user to re-pair with that scope enabled.");
        }

        try {
            $result = ($tool['handler'])($arguments, $ctx);
        } catch (mcpcube_tool_error $e) {
            return self::tool_error($e->getMessage());
        } catch (Throwable $e) {
            rcube::raise_error([
                'code' => 500,
                'type' => 'php',
                'message' => "MCPcube tool '{$name}' failed: " . preg_replace('/[\r\n]+/', ' ', $e->getMessage()),
            ], true, false);

            return self::tool_error('The tool failed unexpectedly. Details were written to the server log.');
        }

        return $result;
    }

    /** @return array<string, mixed> */
    private static function tool_error(string $message): array
    {
        return [
            'content' => [['type' => 'text', 'text' => $message]],
            'isError' => true,
        ];
    }

    /** @return array<string, mixed> */
    private static function error(mixed $id, int $code, string $message): array
    {
        return [
            'jsonrpc' => '2.0',
            'id' => $id,
            'error' => ['code' => $code, 'message' => $message],
        ];
    }

    /** Convenience for tool handlers building a plain-text MCP result. */
    public static function text_result(string $text): array
    {
        return ['content' => [['type' => 'text', 'text' => $text]]];
    }

    /** Convenience for tool handlers returning structured JSON as MCP text content. */
    public static function json_result(mixed $data): array
    {
        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        return [
            'content' => [['type' => 'text', 'text' => $json === false ? '{}' : $json]],
            'structuredContent' => $data,
        ];
    }
}

/** Thrown by a tool handler for an expected, user-facing failure (isError:true result, not a JSON-RPC error). */
final class mcpcube_tool_error extends RuntimeException
{
}

/** Internal: JSON-RPC protocol-level error (bad method, bad params shape). */
final class mcpcube_rpc_error extends RuntimeException
{
}
