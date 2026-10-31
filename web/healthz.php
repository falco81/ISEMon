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
 *   healthz.php?json=1     {"ok":true,"database":true,"maintenance":false,"said":"ok"}
 *
 * In maintenance (Settings → Upgrades and maintenance, isemon --maintenance
 * on; 1.10.266) it says 503 "maintenance", so that a load balancer or the
 * monitoring leaves this server alone until it is back in service.
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
// In maintenance (1.10.266, as otp's /healthz): taken out by hand or for an
// upgrade - the balancer and the monitoring leave it alone until it is back.
// Only that it is, never why: anybody on the list may ask.
$maint = $daemon && !empty($health['maintenance']);
$ok = $daemon && $db && !$maint;
$why = !$daemon ? 'the daemon is not answering' : (!$db ? 'the database is not open'
    : ($maint ? 'maintenance' : 'ok'));

http_response_code($ok ? 200 : 503);
if (isset($_GET['json'])) {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => $ok, 'database' => $db, 'maintenance' => $maint, 'said' => $why]);
} else {
    header('Content-Type: text/plain; charset=utf-8');
    echo $why, "\n";
}
