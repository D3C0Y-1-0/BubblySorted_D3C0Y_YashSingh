<?php

use PHPMailer\PHPMailer\PHPMailer;

function build_mail(string $to, string $subject): PHPMailer
{
    $mail = new PHPMailer(true);
    $mail->setFrom('support@bank.example');
    $mail->addAddress($to);
    $mail->Subject = $subject;
    return $mail;
}
