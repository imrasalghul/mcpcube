<?php

declare(strict_types=1);

/**
 * Identity/settings API surface exposed to sandboxed scripts as
 * `$identities`, built on rcube_user's documented identity API
 * (list_identities, get_identity, insert_identity, update_identity,
 * delete_identity). whoami() needs no scope - it is always safe for an
 * authorized agent to know who and what it is.
 */
final class mcpcube_api_identities
{
    public function __construct(private readonly mcpcube_auth_context $ctx)
    {
    }

    /** @return array<string, mixed> */
    public function whoami(): array
    {
        $rcmail = $this->ctx->rcmail();
        $identity = $rcmail->user->get_identity();

        return [
            'username' => (string) $rcmail->user->get_username(),
            'primary_email' => is_array($identity) ? (string) ($identity['email'] ?? '') : '',
            'agent_id' => $this->ctx->agent_id(),
            'agent_label' => $this->ctx->agent_label(),
            'scopes' => $this->ctx->scopes(),
            'server' => (string) $rcmail->config->get('mcpcube_server_name', 'MCPcube'),
        ];
    }

    /** @return list<array<string, mixed>> */
    public function listIdentities(): array
    {
        $this->require_scope('settings.read');
        $identities = $this->ctx->rcmail()->user->list_identities();

        return array_map(fn (array $identity) => $this->summarize($identity), $identities ?: []);
    }

    /** @return array<string, mixed> */
    public function getIdentity(int $id): array
    {
        $this->require_scope('settings.read');
        $identity = $this->ctx->rcmail()->user->get_identity($id);
        if (!$identity) {
            throw new mcpcube_tool_error("Identity {$id} was not found.");
        }

        return $this->summarize($identity, true);
    }

    /**
     * @param array{name: string, email: string, organization?: string, reply_to?: string, bcc?: string, signature?: string} $fields
     * @return array<string, mixed>
     */
    public function createIdentity(array $fields): array
    {
        $this->require_scope('settings.write');
        $data = $this->normalize_fields($fields);
        if (empty($data['name']) || empty($data['email'])) {
            throw new mcpcube_tool_error('createIdentity requires at least "name" and "email".');
        }

        $id = $this->ctx->rcmail()->user->insert_identity($data);
        if (!$id) {
            throw new mcpcube_tool_error('Could not create the identity.');
        }

        return ['status' => 'created', 'id' => (int) $id];
    }

    /** @param array<string, mixed> $fields @return array<string, mixed> */
    public function updateIdentity(int $id, array $fields): array
    {
        $this->require_scope('settings.write');
        if (!$this->ctx->rcmail()->user->update_identity($id, $this->normalize_fields($fields))) {
            throw new mcpcube_tool_error("Could not update identity {$id}.");
        }

        return ['status' => 'updated', 'id' => $id];
    }

    /** @return array<string, mixed> */
    public function deleteIdentity(int $id, bool $confirm = false, ?string $confirmationToken = null): array
    {
        $this->require_scope('settings.delete');
        $op = 'delete_identity';
        $ids = [(string) $id];

        if (!$confirm) {
            $identity = $this->ctx->rcmail()->user->get_identity($id);
            return [
                'status' => 'confirmation_required',
                'preview' => $identity
                    ? ['id' => $id, 'name' => (string) ($identity['name'] ?? ''), 'email' => (string) ($identity['email'] ?? '')]
                    : ['id' => $id, 'name' => '(not found)', 'email' => ''],
                'confirmation_token' => mcpcube_confirmation::issue($op, $ids, $this->ctx->token_hash()),
            ];
        }

        if (!mcpcube_confirmation::verify($confirmationToken, $op, $ids, $this->ctx->token_hash())) {
            throw new mcpcube_tool_error('Invalid or expired confirmation_token.');
        }

        if (!$this->ctx->rcmail()->user->delete_identity($id)) {
            throw new mcpcube_tool_error("Could not delete identity {$id}. Roundcube always requires at least one remaining identity.");
        }

        return ['status' => 'deleted', 'id' => $id];
    }

    private function require_scope(string $scope): void
    {
        if (!$this->ctx->has_scope($scope)) {
            throw new mcpcube_tool_error("This agent was not granted the '{$scope}' scope. Ask the user to re-pair with that scope enabled.");
        }
    }

    /** @param array<string, mixed> $fields @return array<string, mixed> */
    private function normalize_fields(array $fields): array
    {
        $data = [];
        foreach (['name', 'email', 'organization', 'bcc', 'signature'] as $key) {
            if (isset($fields[$key])) {
                $data[$key] = (string) $fields[$key];
            }
        }
        if (isset($fields['reply_to'])) {
            $data['reply-to'] = (string) $fields['reply_to'];
        }
        if (isset($fields['html_signature'])) {
            $data['html_signature'] = !empty($fields['html_signature']) ? 1 : 0;
        }

        return $data;
    }

    /** @param array<string, mixed> $identity @return array<string, mixed> */
    private function summarize(array $identity, bool $full = false): array
    {
        $out = [
            'id' => (int) ($identity['identity_id'] ?? 0),
            'name' => (string) ($identity['name'] ?? ''),
            'email' => (string) ($identity['email'] ?? ''),
            'is_default' => (bool) ($identity['standard'] ?? false),
        ];

        if ($full) {
            $out['organization'] = (string) ($identity['organization'] ?? '');
            $out['reply_to'] = (string) ($identity['reply-to'] ?? '');
            $out['bcc'] = (string) ($identity['bcc'] ?? '');
            $out['signature'] = (string) ($identity['signature'] ?? '');
        }

        return $out;
    }
}
