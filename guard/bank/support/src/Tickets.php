<?php

declare(strict_types=1);

namespace App;

use PHPMailer\PHPMailer\PHPMailer;

/**
 * Support tickets and the reply mailer. All data is fake. PHPMailer (the seeded vulnerable
 * package) is imported and called, but only to build a reply from constant text; nothing is
 * actually sent and no request input reaches a vulnerable path.
 */
final class Tickets
{
    /** @return list<array{id:int,subject:string,status:string}> */
    public static function all(): array
    {
        return [
            ['id' => 4001, 'subject' => 'Card not working abroad', 'status' => 'open'],
            ['id' => 4002, 'subject' => 'Change of address', 'status' => 'closed'],
            ['id' => 4003, 'subject' => 'Dispute a transaction', 'status' => 'open'],
        ];
    }

    /**
     * Build a reply email with PHPMailer and return its headers as a preview (never sent).
     *
     * @return array{subject:string,mime_prefix:string,library:string}
     */
    public static function replyPreview(): array
    {
        $mail = new PHPMailer(false);
        $mail->setFrom('support@demo-bank.example', 'Demo Bank Support');
        $mail->addAddress('customer@demo-bank.example', 'Demo Customer');
        $mail->Subject = 'Re: your support ticket';
        $mail->Body = 'Thank you for contacting Demo Bank support. This is a demo reply.';
        $mail->preSend();                 // build the MIME message without sending it
        $headers = $mail->getSentMIMEMessage();

        return [
            'subject' => $mail->Subject,
            'mime_prefix' => substr($headers, 0, 16),
            'library' => 'PHPMailer ' . PHPMailer::VERSION,
        ];
    }

    /** File types a customer may attach to a ticket. */
    public const ATTACHMENT_TYPES = ['png', 'jpg', 'jpeg', 'pdf', 'txt'];
    public const ATTACHMENT_MAX_BYTES = 1048576;

    /**
     * Accept a ticket attachment: check its type and size, report its hash, and keep nothing.
     * The Guard in front already inspects uploads; this is the service's own last check.
     *
     * @return array{0:int,1:array<string,mixed>} HTTP status and JSON body
     */
    public static function attach(string $filename, string $content): array
    {
        $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        if ($filename === '' || !in_array($extension, self::ATTACHMENT_TYPES, true)) {
            return [415, ['error' => 'file type not allowed']];
        }
        if (strlen($content) > self::ATTACHMENT_MAX_BYTES) {
            return [413, ['error' => 'file too large']];
        }

        return [201, [
            'ticket' => 4101,
            'filename' => basename($filename),
            'size' => strlen($content),
            'sha256' => hash('sha256', $content),
            'stored' => false,
        ]];
    }
}
