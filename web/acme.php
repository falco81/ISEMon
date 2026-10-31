<?php
/**
 * acme.php — the answer to an ACME CA's HTTP-01 challenge (1.10.251; after
 * otp's acme.php, 1.0.169).
 *
 * nginx's port-80 server sends http://NAME/.well-known/acme-challenge/TOKEN
 * here (root's helper puts that location in while Settings → Automatic
 * certificates checks the name by HTTP-01). The answer is kept in isemon's
 * database for as long as an order waits on that token; the daemon gives it
 * only then, and nothing else is said - so anybody may ask, the CA among
 * them, whoever else the pages are for.
 */
declare(strict_types=1);

header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

require_once __DIR__ . '/isemon-api.php';

function acme_not_found(): void
{
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo "not found\n";
    exit;
}

$method = (string) ($_SERVER['REQUEST_METHOD'] ?? 'GET');
if ($method !== 'GET' && $method !== 'HEAD') {
    http_response_code(405);
    header('Allow: GET, HEAD');
    exit;
}
$uri = (string) ($_SERVER['REQUEST_URI'] ?? '');
$path = (string) parse_url($uri, PHP_URL_PATH);
if (!preg_match('#^/\.well-known/acme-challenge/([A-Za-z0-9_-]{8,256})$#', $path, $m)) {
    acme_not_found();
}
$got = isemon_get('/api/acme/challenge?token=' . rawurlencode($m[1]), 10.0);
if (!is_array($got) || !isset($got['auth']) || !is_string($got['auth'])
        || !preg_match('#^[A-Za-z0-9_.-]{8,600}$#', $got['auth'])) {
    acme_not_found();
}
header('Content-Type: application/octet-stream');
echo $got['auth'];
