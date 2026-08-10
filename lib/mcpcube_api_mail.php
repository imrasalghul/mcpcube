<?php

declare(strict_types=1);

/**
 * Mail API surface exposed to sandboxed scripts as `$mail`. Every method
 * checks its own OAuth scope against the calling agent before touching
 * IMAP/SMTP. Every method here is public; nothing else on this class is, so
 * the reflection-based dispatch in mcpcube_sandbox can never call anything
 * unintended.
 *
 * Integration note: list/search/flag/move/create/delete folder operations
 * use rcube_imap's documented public API (list_folders_subscribed,
 * folder_status, search, get_message_headers, set_flag/unset_flag,
 * move_message, create_folder, delete_folder, clear_folder) and
 * sendMessage() uses the bundled Mail_mime + rcmail::smtp_init()/rcube_smtp.
 * These calls were written against Roundcube 1.7's documented plugin API
 * surface but were not executed against a live instance while building this
 * plugin - smoke-test every method (especially sendMessage) against a real
 * Roundcube 1.7.3 install before relying on it in production.
 */
final class mcpcube_api_mail
{
    public function __construct(private readonly mcpcube_auth_context $ctx)
    {
    }

    /** @return list<array{name: string, unread: int, total: int, delimiter: string}> */
    public function listFolders(): array
    {
        $this->require_scope('mail.read');
        $storage = $this->ctx->rcmail()->get_storage();
        $delimiter = (string) $storage->get_hierarchy_delimiter();
        $result = [];

        foreach ($storage->list_folders_subscribed() as $folder) {
            $status = $storage->folder_status($folder) ?: [];
            $result[] = [
                'name' => $folder,
                'unread' => (int) ($status['unseen'] ?? 0),
                'total' => (int) ($status['messages'] ?? 0),
                'delimiter' => $delimiter,
            ];
        }

        return $result;
    }

    /** @return list<array<string, mixed>> */
    public function listMessages(string $folder = 'INBOX', int $limit = 100, int $offset = 0): array
    {
        $this->require_scope('mail.read');
        $limit = max(1, min(200, $limit));
        $offset = max(0, $offset);

        $storage = $this->ctx->rcmail()->get_storage();
        $index = $storage->search($folder, 'ALL');
        $uids = array_reverse($index->get());
        $slice = array_slice($uids, $offset, $limit);

        $messages = [];
        foreach ($slice as $uid) {
            $header = $storage->get_message_headers($uid, $folder);
            if ($header) {
                $messages[] = $this->summarize_header($header, $folder);
            }
        }

        return $messages;
    }

    /** @return array<string, mixed> */
    public function getMessage(int $uid, string $folder = 'INBOX'): array
    {
        $this->require_scope('mail.read');
        $message = new rcube_message((string) $uid, $folder);

        if (empty($message->headers)) {
            throw new mcpcube_tool_error("Message {$uid} was not found in {$folder}.");
        }

        $attachments = [];
        foreach ($message->attachments as $part) {
            $attachments[] = [
                'filename' => (string) ($part->filename ?? '(unnamed)'),
                'mimetype' => (string) ($part->mimetype ?? 'application/octet-stream'),
                'size' => (int) ($part->size ?? 0),
                'part_id' => (string) ($part->mime_id ?? ''),
            ];
        }

        $bodyText = $message->first_text_part();
        if ($bodyText === null) {
            $html = $message->first_html_part();
            $bodyText = $html !== null ? trim(strip_tags($html)) : '';
        }

        return [
            'uid' => $uid,
            'folder' => $folder,
            'subject' => (string) $message->subject,
            'from' => (string) ($message->headers->from ?? ''),
            'to' => (string) ($message->headers->to ?? ''),
            'cc' => (string) ($message->headers->cc ?? ''),
            'date' => (string) ($message->headers->date ?? ''),
            'message_id' => (string) ($message->headers->messageID ?? ''),
            'body_text' => (string) $bodyText,
            'attachments' => $attachments,
        ];
    }

    /** @return list<array<string, mixed>> */
    public function searchMessages(string $query, string $folder = 'INBOX', int $limit = 50): array
    {
        $this->require_scope('mail.read');
        $limit = max(1, min(200, $limit));

        if (trim($query) === '') {
            throw new mcpcube_tool_error('searchMessages requires a non-empty query.');
        }

        $storage = $this->ctx->rcmail()->get_storage();
        $escaped = str_replace(['\\', '"'], ['\\\\', '\\"'], $query);
        $index = $storage->search($folder, 'TEXT "' . $escaped . '"');
        $uids = array_slice(array_reverse($index->get()), 0, $limit);

        $messages = [];
        foreach ($uids as $uid) {
            $header = $storage->get_message_headers($uid, $folder);
            if ($header) {
                $messages[] = $this->summarize_header($header, $folder);
            }
        }

        return $messages;
    }

    /**
     * @param array{to: string, subject: string, cc?: string, bcc?: string, body_text?: string, body_html?: string, in_reply_to?: string, references?: string} $message
     * @return array<string, mixed>
     */
    public function sendMessage(array $message): array
    {
        $this->require_scope('mail.write');

        $to = trim((string) ($message['to'] ?? ''));
        $subject = (string) ($message['subject'] ?? '');
        if ($to === '' || $subject === '') {
            throw new mcpcube_tool_error('sendMessage requires at least "to" and "subject".');
        }
        foreach (['to', 'subject', 'cc', 'bcc', 'in_reply_to', 'references'] as $field) {
            if (isset($message[$field]) && preg_match('/[\r\n]/', (string) $message[$field])) {
                throw new mcpcube_tool_error("sendMessage header '{$field}' must not contain line breaks.");
            }
        }

        $rcmail = $this->ctx->rcmail();
        $identity = $rcmail->user->get_identity();
        $from = is_array($identity) && !empty($identity['email']) ? (string) $identity['email'] : (string) $rcmail->user->get_username();

        $mime = new Mail_mime(['eol' => "\r\n"]);
        $mime->setParam('head_charset', 'UTF-8');
        $mime->setParam('text_charset', 'UTF-8');
        $mime->setParam('html_charset', 'UTF-8');

        if (!empty($message['body_text'])) {
            $mime->setTXTBody((string) $message['body_text']);
        }
        if (!empty($message['body_html'])) {
            $mime->setHTMLBody((string) $message['body_html']);
        }
        if (empty($message['body_text']) && empty($message['body_html'])) {
            $mime->setTXTBody('');
        }

        $headers = [
            'From' => $from,
            'To' => $to,
            'Subject' => $subject,
            'Date' => gmdate('r'),
            'Message-ID' => $rcmail->gen_message_id(),
            'X-Mailer' => (string) $rcmail->config->get('mcpcube_server_name', 'MCPcube'),
        ];
        if (!empty($message['cc'])) {
            $headers['Cc'] = (string) $message['cc'];
        }
        if (!empty($message['in_reply_to'])) {
            $headers['In-Reply-To'] = (string) $message['in_reply_to'];
        }
        if (!empty($message['references'])) {
            $headers['References'] = (string) $message['references'];
        }
        $mime->headers($headers);

        $recipients = [$to];
        if (!empty($message['cc'])) {
            $recipients[] = (string) $message['cc'];
        }
        if (!empty($message['bcc'])) {
            $recipients[] = (string) $message['bcc'];
        }

        if (!$rcmail->smtp_init(true)) {
            throw new mcpcube_tool_error('Could not initialize the SMTP connection.');
        }

        $headerText = $mime->txtHeaders();
        $bodyText = $mime->get();
        $sent = $rcmail->smtp->send_mail($from, $recipients, $headerText, $bodyText);
        $response = $rcmail->smtp->get_response();
        $rcmail->smtp->reset();

        if (!$sent) {
            throw new mcpcube_tool_error('The mail server rejected the message: ' . implode(' ', (array) $response));
        }

        return ['status' => 'sent', 'to' => $to, 'subject' => $subject, 'message_id' => $headers['Message-ID']];
    }

    /** @return array<string, mixed> */
    public function moveMessage(int $uid, string $folder, string $targetFolder): array
    {
        $this->require_scope('mail.write');
        $storage = $this->ctx->rcmail()->get_storage();

        if (!$storage->move_message((string) $uid, $targetFolder, $folder)) {
            throw new mcpcube_tool_error("Could not move message {$uid} from {$folder} to {$targetFolder}.");
        }

        return ['status' => 'moved', 'uid' => $uid, 'from' => $folder, 'to' => $targetFolder];
    }

    /** @return array<string, mixed> */
    public function flagMessage(int $uid, string $folder, string $flag, bool $set = true): array
    {
        $this->require_scope('mail.write');
        $allowed = ['SEEN', 'FLAGGED', 'ANSWERED', 'DRAFT'];
        $flag = strtoupper($flag);
        if (!in_array($flag, $allowed, true)) {
            throw new mcpcube_tool_error('flag must be one of: ' . implode(', ', $allowed));
        }

        $storage = $this->ctx->rcmail()->get_storage();
        $ok = $set ? $storage->set_flag($uid, $flag, $folder) : $storage->unset_flag($uid, $flag, $folder);
        if (!$ok) {
            throw new mcpcube_tool_error("Could not update flag {$flag} on message {$uid}.");
        }

        return ['status' => 'ok', 'uid' => $uid, 'flag' => $flag, 'set' => $set];
    }

    /** @return array<string, mixed> */
    public function createFolder(string $name, ?string $parent = null): array
    {
        $this->require_scope('mail.write');
        $storage = $this->ctx->rcmail()->get_storage();
        $delimiter = (string) $storage->get_hierarchy_delimiter();
        $fullName = $parent !== null && $parent !== '' ? $parent . $delimiter . $name : $name;

        if (!$storage->create_folder($fullName)) {
            throw new mcpcube_tool_error("Could not create folder {$fullName}.");
        }
        $storage->subscribe($fullName);

        return ['status' => 'created', 'name' => $fullName];
    }

    /**
     * Two-step delete: call once without $confirm to get a preview and a
     * confirmation_token; call again with confirm:true and that token to
     * actually delete.
     *
     * @param int|list<int> $uid
     * @return array<string, mixed>
     */
    public function deleteMessage(int|array $uid, string $folder = 'INBOX', bool $confirm = false, ?string $confirmationToken = null): array
    {
        $this->require_scope('mail.delete');
        $uids = array_values(array_unique(array_map('intval', is_array($uid) ? $uid : [$uid])));
        if ($uids === []) {
            throw new mcpcube_tool_error('No message uid given.');
        }

        $storage = $this->ctx->rcmail()->get_storage();
        $ids = array_map('strval', $uids);
        $op = 'delete_message:' . $folder;

        if (!$confirm) {
            $preview = [];
            foreach ($uids as $u) {
                $header = $storage->get_message_headers($u, $folder);
                $preview[] = $header
                    ? ['uid' => $u, 'subject' => (string) ($header->subject ?? '(no subject)'), 'from' => (string) ($header->from ?? '')]
                    : ['uid' => $u, 'subject' => '(not found)', 'from' => ''];
            }

            return [
                'status' => 'confirmation_required',
                'folder' => $folder,
                'preview' => $preview,
                'confirmation_token' => mcpcube_confirmation::issue($op, $ids, $this->ctx->token_hash()),
            ];
        }

        if (!mcpcube_confirmation::verify($confirmationToken, $op, $ids, $this->ctx->token_hash())) {
            throw new mcpcube_tool_error('Invalid or expired confirmation_token. Call deleteMessage again without confirm to get a fresh one.');
        }

        if (!$storage->delete_message($uids, $folder)) {
            throw new mcpcube_tool_error('Could not delete the message(s).');
        }

        return ['status' => 'deleted', 'uids' => $uids, 'folder' => $folder];
    }

    /** @return array<string, mixed> */
    public function emptyFolder(string $folder, bool $confirm = false, ?string $confirmationToken = null): array
    {
        $this->require_scope('mail.delete');
        $storage = $this->ctx->rcmail()->get_storage();
        $status = $storage->folder_status($folder) ?: [];
        $count = (int) ($status['messages'] ?? 0);
        $op = 'empty_folder';

        if (!$confirm) {
            return [
                'status' => 'confirmation_required',
                'folder' => $folder,
                'message_count' => $count,
                'confirmation_token' => mcpcube_confirmation::issue($op, [$folder], $this->ctx->token_hash()),
            ];
        }

        if (!mcpcube_confirmation::verify($confirmationToken, $op, [$folder], $this->ctx->token_hash())) {
            throw new mcpcube_tool_error('Invalid or expired confirmation_token.');
        }

        if (!$storage->clear_folder($folder)) {
            throw new mcpcube_tool_error("Could not empty folder {$folder}.");
        }

        return ['status' => 'emptied', 'folder' => $folder, 'messages_removed' => $count];
    }

    /** @return array<string, mixed> */
    public function deleteFolder(string $name, bool $confirm = false, ?string $confirmationToken = null): array
    {
        $this->require_scope('mail.delete');
        $op = 'delete_folder';

        if (!$confirm) {
            return [
                'status' => 'confirmation_required',
                'folder' => $name,
                'confirmation_token' => mcpcube_confirmation::issue($op, [$name], $this->ctx->token_hash()),
            ];
        }

        if (!mcpcube_confirmation::verify($confirmationToken, $op, [$name], $this->ctx->token_hash())) {
            throw new mcpcube_tool_error('Invalid or expired confirmation_token.');
        }

        $storage = $this->ctx->rcmail()->get_storage();
        if (!$storage->delete_folder($name)) {
            throw new mcpcube_tool_error("Could not delete folder {$name}.");
        }

        return ['status' => 'deleted', 'folder' => $name];
    }

    private function require_scope(string $scope): void
    {
        if (!$this->ctx->has_scope($scope)) {
            throw new mcpcube_tool_error("This agent was not granted the '{$scope}' scope. Ask the user to re-pair with that scope enabled.");
        }
    }

    /** @return array<string, mixed> */
    private function summarize_header(rcube_message_header $header, string $folder): array
    {
        return [
            'uid' => (int) $header->uid,
            'folder' => $folder,
            'subject' => (string) ($header->subject ?? '(no subject)'),
            'from' => (string) ($header->from ?? ''),
            'to' => (string) ($header->to ?? ''),
            'date' => isset($header->timestamp) ? gmdate('c', (int) $header->timestamp) : (string) ($header->date ?? ''),
            'size' => (int) ($header->size ?? 0),
            'seen' => (bool) ($header->flags['SEEN'] ?? false),
            'flagged' => (bool) ($header->flags['FLAGGED'] ?? false),
            'answered' => (bool) ($header->flags['ANSWERED'] ?? false),
        ];
    }
}
