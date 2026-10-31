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
}
