<?php

declare(strict_types=1);

/**
 * Contacts API surface exposed to sandboxed scripts as `$contacts`, built on
 * rcube_addressbook's documented public API (list_records, search,
 * get_record, insert, update, delete). Only the account's single default
 * writable address book is used (rcmail::get_address_book(TYPE_DEFAULT, true)) -
 * multi-addressbook/LDAP setups are out of scope for v1. As with the mail
 * facade, this was written against Roundcube 1.7's documented API surface
 * but not executed against a live instance; smoke-test before production use.
 */
final class mcpcube_api_contacts
{
    public function __construct(private readonly mcpcube_auth_context $ctx)
    {
    }

    /** @return list<array<string, mixed>> */
    public function listContacts(?string $search = null, int $limit = 50, int $offset = 0): array
    {
        $this->require_scope('contacts.read');
        $limit = max(1, min(200, $limit));
        $book = $this->book();
        $book->set_pagesize($limit);
        $book->set_page((int) floor(max(0, $offset) / $limit) + 1);

        $result = ($search !== null && trim($search) !== '')
            ? $book->search(['name', 'email'], $search, 0, true)
            : $book->list_records();

        $records = [];
        foreach ($result->records ?? [] as $record) {
            $records[] = $this->summarize_record($record);
        }

        return $records;
    }

    /** @return array<string, mixed> */
    public function getContact(string $id): array
    {
        $this->require_scope('contacts.read');
        $record = $this->book()->get_record($id, true);
        if (!$record) {
            throw new mcpcube_tool_error("Contact {$id} was not found.");
        }

        return $this->summarize_record($record, true);
    }

    /**
     * @param array{name?: string, firstname?: string, surname?: string, organization?: string, email?: string|list<string>, phone?: string|list<string>, notes?: string} $fields
     * @return array<string, mixed>
     */
    public function createContact(array $fields): array
    {
        $this->require_scope('contacts.write');
        $id = $this->book()->insert($this->normalize_fields($fields));
        if (!$id) {
            throw new mcpcube_tool_error('Could not create the contact.');
        }

        return ['status' => 'created', 'id' => (string) $id];
    }

    /**
     * @param array<string, mixed> $fields
     * @return array<string, mixed>
     */
    public function updateContact(string $id, array $fields): array
    {
        $this->require_scope('contacts.write');
        if (!$this->book()->update($id, $this->normalize_fields($fields))) {
            throw new mcpcube_tool_error("Could not update contact {$id}.");
        }

        return ['status' => 'updated', 'id' => $id];
    }

    /**
     * @param string|list<string> $id
     * @return array<string, mixed>
     */
    public function deleteContact(string|array $id, bool $confirm = false, ?string $confirmationToken = null): array
    {
        $this->require_scope('contacts.delete');
        $ids = array_values(array_unique(array_map('strval', is_array($id) ? $id : [$id])));
        if ($ids === []) {
            throw new mcpcube_tool_error('No contact id given.');
        }

        $op = 'delete_contact';

        if (!$confirm) {
            $book = $this->book();
            $preview = [];
            foreach ($ids as $cid) {
                $record = $book->get_record($cid, true);
                $preview[] = $record
                    ? ['id' => $cid, 'name' => (string) ($record['name'] ?? ''), 'email' => $this->first_email($record)]
                    : ['id' => $cid, 'name' => '(not found)', 'email' => ''];
            }

            return [
                'status' => 'confirmation_required',
                'preview' => $preview,
                'confirmation_token' => mcpcube_confirmation::issue($op, $ids, $this->ctx->token_hash()),
            ];
        }

        if (!mcpcube_confirmation::verify($confirmationToken, $op, $ids, $this->ctx->token_hash())) {
            throw new mcpcube_tool_error('Invalid or expired confirmation_token. Call deleteContact again without confirm to get a fresh one.');
        }

        if (!$this->book()->delete($ids, true)) {
            throw new mcpcube_tool_error('Could not delete the contact(s).');
        }

        return ['status' => 'deleted', 'ids' => $ids];
    }

    private function book(): rcube_addressbook
    {
        $book = $this->ctx->rcmail()->get_address_book(rcube_addressbook::TYPE_DEFAULT, true);
        if (!$book) {
            throw new mcpcube_tool_error('No writable address book is configured for this account.');
        }

        return $book;
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
        foreach (['name', 'firstname', 'surname', 'prefix', 'suffix', 'organization', 'jobtitle', 'notes'] as $key) {
            if (isset($fields[$key])) {
                $data[$key] = (string) $fields[$key];
            }
        }
        if (isset($fields['email'])) {
            $data['email'] = is_array($fields['email']) ? array_map('strval', $fields['email']) : (string) $fields['email'];
        }
        if (isset($fields['phone'])) {
            $data['phone'] = is_array($fields['phone']) ? array_map('strval', $fields['phone']) : (string) $fields['phone'];
        }
        if ($data === []) {
            throw new mcpcube_tool_error('No recognized contact fields were given (name, firstname, surname, organization, email, phone, notes).');
        }

        return $data;
    }

    /** @param array<string, mixed> $record */
    private function first_email(array $record): string
    {
        $email = $record['email'] ?? '';
        return is_array($email) ? (string) ($email[0] ?? '') : (string) $email;
    }

    /** @param array<string, mixed> $record @return array<string, mixed> */
    private function summarize_record(array $record, bool $full = false): array
    {
        $out = [
            'id' => (string) ($record['ID'] ?? $record['id'] ?? ''),
            'name' => (string) ($record['name'] ?? ''),
            'email' => $this->first_email($record),
        ];

        if ($full) {
            $out['firstname'] = (string) ($record['firstname'] ?? '');
            $out['surname'] = (string) ($record['surname'] ?? '');
            $out['organization'] = (string) ($record['organization'] ?? '');
            $out['phone'] = $record['phone'] ?? null;
            $out['notes'] = (string) ($record['notes'] ?? '');
        }

        return $out;
    }
}
