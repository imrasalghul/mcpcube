<?php

declare(strict_types=1);

/** OAuth metadata, PKCE authorization-code, refresh-token, and registration support. */
final class mcpcube_oauth
{
    public const PRM_PATH = '/.well-known/oauth-protected-resource';
    public const AS_PATH = '/.well-known/oauth-authorization-server';

    public static function metadata(bool $resource = false): array
    {
        $base = rtrim((string) rcmail::get_instance()->config->get('mcpcube_public_url', ''), '/');
        if ($resource) {
            return [
                'resource' => $base . '/mcp',
                'authorization_servers' => [$base],
                'scopes_supported' => (array) rcmail::get_instance()->config->get('mcpcube_available_scopes', []),
                'bearer_methods_supported' => ['header'],
            ];
        }

        return [
            'issuer' => $base,
            'authorization_endpoint' => $base . '/oauth/authorize',
            'token_endpoint' => $base . '/oauth/token',
            'registration_endpoint' => $base . '/oauth/register',
            'response_types_supported' => ['code'],
            'grant_types_supported' => ['authorization_code'],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['none'],
            'scopes_supported' => (array) rcmail::get_instance()->config->get('mcpcube_available_scopes', []),
        ];
    }

    public static function json(array $body, int $status = 200): never
    {
        http_response_code($status);
        header('Content-Type: application/json');
        header('Cache-Control: no-store');
        echo json_encode($body, JSON_UNESCAPED_SLASHES);
        exit;
    }

    public static function register(): void
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') self::json(['error' => 'invalid_request'], 405);
        $body = json_decode((string) file_get_contents('php://input'), true);
        if (!is_array($body)) self::json(['error' => 'invalid_client_metadata'], 400);
        $uris = $body['redirect_uris'] ?? [];
        if (!is_array($uris) || $uris === []) self::json(['error' => 'invalid_redirect_uri'], 400);
        foreach ($uris as $uri) {
            if (!is_string($uri) || !self::valid_redirect($uri)) self::json(['error' => 'invalid_redirect_uri'], 400);
        }
        $client = 'mcpcube_' . bin2hex(random_bytes(16));
        $base = rtrim((string) rcmail::get_instance()->config->get('mcpcube_public_url', ''), '/');
        $db = rcmail::get_instance()->get_dbh();
        $table = $db->table_name('mcpcube_oauth_clients', true);
        $result = $db->query("INSERT INTO {$table} (`client_id`, `client_name`, `redirect_uris`, `created`) VALUES (?, ?, ?, " . $db->now() . ')',
            $client, mb_substr((string) ($body['client_name'] ?? 'MCP client'), 0, 120), json_encode(array_values($uris)));
        if ($db->is_error($result)) self::json(['error' => 'invalid_client_metadata'], 400);
        self::json(['client_id' => $client, 'client_name' => (string) ($body['client_name'] ?? 'MCP client'), 'redirect_uris' => array_values($uris), 'token_endpoint_auth_method' => 'none'], 201);
    }

    public static function authorize(): void
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'GET') self::json(['error' => 'invalid_request'], 405);
        $base = rtrim((string) rcmail::get_instance()->config->get('mcpcube_public_url', ''), '/');
        $client = self::client((string) ($_GET['client_id'] ?? ''));
        $redirect = (string) ($_GET['redirect_uri'] ?? '');
        $state = (string) ($_GET['state'] ?? '');
        $challenge = (string) ($_GET['code_challenge'] ?? '');
        if ((string) ($_GET['response_type'] ?? '') !== 'code' || ($_GET['code_challenge_method'] ?? '') !== 'S256'
            || $challenge === '' || !self::valid_redirect($redirect) || !in_array($redirect, $client['redirects'], true)
        ) self::redirect_error($redirect, $state, 'invalid_request');

        $requested = preg_split('/\s+/', trim((string) ($_GET['scope'] ?? '')), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        $available = (array) rcmail::get_instance()->config->get('mcpcube_available_scopes', []);
        if ($requested === []) $requested = (array) rcmail::get_instance()->config->get('mcpcube_default_scopes', []);
        if (array_diff($requested, $available) !== []) self::redirect_error($redirect, $state, 'invalid_scope');

        $db = rcmail::get_instance()->get_dbh();
        $table = $db->table_name('mcpcube_oauth_requests', true);
        $request = bin2hex(random_bytes(24));
        $db->query("INSERT INTO {$table} (`request_id`,`client_id`,`redirect_uri`,`state`,`code_challenge`,`scope`,`resource`,`created`,`expires`) VALUES (?, ?, ?, ?, ?, ?, ?, " . $db->now() . ', ?)',
            $request, $client['id'], $redirect, $state, $challenge, implode(',', $requested), (string) ($_GET['resource'] ?? ($base . '/mcp')), gmdate('Y-m-d H:i:s', time() + 600));
        $devices = $db->table_name('mcpcube_device_codes', true);
        $device = mcpcube_crypto::random_hex(32);
        $userCode = mcpcube_crypto::random_user_code();
        $db->query("INSERT INTO {$devices} (`device_code`,`user_code`,`client_label`,`requested_scopes`,`status`,`created`,`expires`,`poll_interval`,`oauth_request_id`) VALUES (?, ?, ?, ?, 'pending', " . $db->now() . ', ?, 5, ?)',
            $device, $userCode, (string) $client['name'], implode(',', $requested), gmdate('Y-m-d H:i:s', time() + 600), $request);
        header('Location: ' . $base . '/?_task=settings&_action=plugin.mcpcube-pair&user_code=' . rawurlencode($userCode));
        exit;
    }

    public static function token(): void
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') self::json(['error' => 'invalid_request'], 405);
        $input = $_POST;
        if (stripos((string) ($_SERVER['CONTENT_TYPE'] ?? ''), 'application/json') !== false) $input = json_decode((string) file_get_contents('php://input'), true) ?: [];
        $grant = (string) ($input['grant_type'] ?? '');
        $db = rcmail::get_instance()->get_dbh();
        $table = $db->table_name('mcpcube_oauth_codes', true);
        if ($grant === 'authorization_code') {
            $code = (string) ($input['code'] ?? '');
            $row = self::code_row($db, $table, $code);
            if (!$row || (string) $row['client_id'] !== (string) ($input['client_id'] ?? '') || !hash_equals((string) $row['redirect_uri'], (string) ($input['redirect_uri'] ?? ''))
                || !hash_equals((string) $row['code_challenge'], self::challenge((string) ($input['code_verifier'] ?? '')))) self::json(['error' => 'invalid_grant'], 400);
            $db->query("UPDATE {$table} SET `used` = 1 WHERE `id` = ? AND `used` = 0", $row['id']);
            if ($db->affected_rows() !== 1) self::json(['error' => 'invalid_grant'], 400);
            $access = mcpcube_crypto::decrypt_secret((string) $row['access_ciphertext'], 'oauth-access:' . $row['request_id'], mcpcube_crypto::config_key());
            if (!is_string($access)) self::json(['error' => 'server_error'], 500);
            self::json(['access_token' => $access, 'token_type' => 'Bearer', 'expires_in' => (int) $row['access_expires'], 'scope' => str_replace(',', ' ', (string) $row['scope'])]);
        }
        self::json(['error' => 'unsupported_grant_type'], 400);
    }

    public static function challenge(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    private static function code_row(rcube_db $db, string $table, string $code): ?array
    {
        if ($code === '' || strlen($code) > 200) return null;
        $hash = hash('sha256', $code);
        $result = $db->query("SELECT * FROM {$table} WHERE `code_hash` = ? AND `used` = 0 AND `expires` > " . $db->now(), $hash);
        $row = $db->fetch_assoc($result);
        return is_array($row) ? $row : null;
    }

    private static function client(string $id): array
    {
        $db = rcmail::get_instance()->get_dbh(); $table = $db->table_name('mcpcube_oauth_clients', true);
        $result = $db->query("SELECT * FROM {$table} WHERE `client_id` = ?", $id); $row = $db->fetch_assoc($result);
        if (!is_array($row)) self::json(['error' => 'unauthorized_client'], 400);
        $redirects = json_decode((string) $row['redirect_uris'], true);
        return ['id' => (string) $row['client_id'], 'name' => (string) $row['client_name'], 'redirects' => is_array($redirects) ? $redirects : []];
    }

    private static function valid_redirect(string $uri): bool
    {
        $p = parse_url($uri); return is_array($p) && in_array(strtolower((string) ($p['scheme'] ?? '')), ['https', 'http'], true)
            && (($p['scheme'] === 'http' && in_array(strtolower((string) ($p['host'] ?? '')), ['localhost', '127.0.0.1', '[::1]'], true)) || strtolower((string) ($p['scheme'] ?? '')) === 'https')
            && !isset($p['fragment']);
    }

    private static function redirect_error(string $redirect, string $state, string $error): never
    {
        if (!self::valid_redirect($redirect)) self::json(['error' => $error], 400);
        header('Location: ' . $redirect . '?' . http_build_query(['error' => $error, 'state' => $state])); exit;
    }
}
