<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use App\Tickets;

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

// access log, in the format hedwig's evidence reader reads; client IP from X-Forwarded-For
$ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? ($_SERVER['REMOTE_ADDR'] ?? '-');
$ip = trim(explode(',', $ip)[0]);

$routes = [
    '/health' => fn () => ['status' => 'ok'],
    '/' => fn () => ['service' => 'support'],
    '/tickets' => fn () => ['tickets' => Tickets::all()],
    '/reply-preview' => fn () => Tickets::replyPreview(),
];

if ($method === 'POST' && $path === '/attachments') {
    $upload = $_FILES['file'] ?? null;
    $name = $upload['name'] ?? ($_SERVER['HTTP_X_FILENAME'] ?? '');
    $content = $upload && is_uploaded_file($upload['tmp_name'])
        ? (string) file_get_contents($upload['tmp_name'])
        : (string) file_get_contents('php://input');
    [$status, $body] = Tickets::attach((string) $name, $content);
} elseif ($method === 'GET' && isset($routes[$path])) {
    $status = 200;
    $body = $routes[$path]();
} else {
    $status = 404;
    $body = ['error' => 'not found'];
}

http_response_code($status);
header('Content-Type: application/json');
$log = getenv('ACCESS_LOG') ?: (__DIR__ . '/../logs/access.log');
@mkdir(dirname($log), 0777, true);
$line = sprintf("%s %s - \"%s %s HTTP/1.1\" %d\n", gmdate('c'), $ip, $method,
    $_SERVER['REQUEST_URI'] ?? $path, $status);
@file_put_contents($log, $line, FILE_APPEND);

echo json_encode($body);
