<?php
/**
 * healthz.php — whether this isemon is well, for monitoring (1.10.222).
 *
 * Zabbix, Nagios, Uptime Kuma or a load balancer asks this with nobody
 * signed in: 200 and "ok" when the daemon answers and its database is open,
 * 503 and why not otherwise. Nothing else is said - no names, no counts, no
 * addresses - and who may ask is decided by nginx (Settings → Firewall and
 * access → The health check; as the dashboard unless set otherwise).
 *
 *   healthz.php            200 ok  |  503 <why>   (text/plain)
 *   healthz.php?json=1     {"ok":true,"database":true,"said":"ok"}
 *
 * The version is not said: a page anybody on the list may ask is no place
 * to tell them which version is running.
 */
declare(strict_types=1);

header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");

require_once __DIR__ . '/isemon-api.php';

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET' && ($_SERVER['REQUEST_METHOD'] ?? '') !== 'HEAD') {
    http_response_code(405);
    header('Allow: GET, HEAD');
    exit;
}

$health = isemon_get('/api/health', 5.0);
$daemon = is_array($health);
$db = $daemon && !empty($health['database']['ok']);
$ok = $daemon && $db;
$why = !$daemon ? 'the daemon is not answering' : (!$db ? 'the database is not open' : 'ok');

http_response_code($ok ? 200 : 503);
if (isset($_GET['json'])) {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => $ok, 'database' => $db, 'said' => $why]);
} else {
    header('Content-Type: text/plain; charset=utf-8');
    echo $why, "\n";
}
