<?php

declare(strict_types=1);

use App\Tickets;
use PHPUnit\Framework\TestCase;

final class TicketsTest extends TestCase
{
    public function testThereAreFakeTickets(): void
    {
        $tickets = Tickets::all();
        $this->assertCount(3, $tickets);
        $this->assertSame(4001, $tickets[0]['id']);
    }

    public function testReplyIsBuiltWithPhpmailer(): void
    {
        $preview = Tickets::replyPreview();
        $this->assertSame('Re: your support ticket', $preview['subject']);
        $this->assertStringContainsString('PHPMailer 6.4.1', $preview['library']);
        $this->assertNotEmpty($preview['mime_prefix']);
    }

    public function testAnAllowedAttachmentIsAcceptedAndKeptNowhere(): void
    {
        [$status, $body] = Tickets::attach('receipt.png', 'png bytes');
        $this->assertSame(201, $status);
        $this->assertFalse($body['stored']);
        $this->assertSame(hash('sha256', 'png bytes'), $body['sha256']);
    }

    public function testOtherFileTypesAreRefused(): void
    {
        [$status] = Tickets::attach('payload.exe', 'x');
        $this->assertSame(415, $status);
        [$status] = Tickets::attach('invoice.locked', 'x');
        $this->assertSame(415, $status);
    }
}
