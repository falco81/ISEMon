<?php
/**
 * banfeed.php — the ban list, published for a firewall to fetch.
 *
 * A Cisco FTD (through its FMC's Security Intelligence) or a FortiGate
 * (an external threat feed) fetches this by itself, every few minutes, with
 * nobody signed in. What it may have is decided by the daemon: whether
 * anything is published at all, whether the key is right, whether the
 * address asking may ask. This file only carries the question there and the
 * answer back.
 *
 *   banfeed.php                  the format saved in the settings
 *   banfeed.php?f=ftd            one address or range per line
 *   banfeed.php?f=ftd&md5=1      the MD5 of that, which the FMC asks first
 *   banfeed.php?f=fortigate      the same shape, for a FortiGate
 *   banfeed.php?f=opnsense       the same shape, for an OPNsense URL Table alias
 *   banfeed.php?f=pfsense        the same shape, for a pfSense URL Table or pfBlockerNG
 *   banfeed.php?f=plain          ...with a few comments for a person
 *   banfeed.php?f=json           for a script
 *   &family=ipv4 | ipv6          one family only
 *
 * By default nothing is asked: who may fetch it is decided by the web
 * server's allow list and by `banfeed_from`. `banfeed_auth` can ask for a key
 * in the URL (`k=`, for an FMC, which has nowhere to type a password) or for
 * a user name and a password by HTTP basic authentication (a FortiGate).
 */
declare(strict_types=1);

header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");

require_once __DIR__ . '/isemon-api.php';

function banfeed_say(int $status, string $words, array $more = []): void
{
    http_response_code($status);
    header('Content-Type: text/plain; charset=utf-8');
    foreach ($more as $line) {
        header($line);
    }
    echo $words;
    exit;
}

$method = (string) ($_SERVER['REQUEST_METHOD'] ?? 'GET');
if ($method !== 'GET' && $method !== 'HEAD') {
    banfeed_say(405, "only GET\n", ['Allow: GET, HEAD']);
}

/* The key, where the settings ask for one, is in the URL. A user name and
   a password, where they ask for those, come by HTTP basic authentication:
   PHP fills PHP_AUTH_USER and PHP_AUTH_PW itself under mod_php, and behind
   FastCGI only the header may have come through, so it is read from there as
   well. Which of them counts is the daemon's to say. */
$key = (string) ($_GET['k'] ?? '');
$user = (string) ($_SERVER['PHP_AUTH_USER'] ?? '');
$password = (string) ($_SERVER['PHP_AUTH_PW'] ?? '');
if ($user === '' && $password === '') {
    $auth = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? ($_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? ''));
    if (stripos($auth, 'basic ') === 0) {
        $pair = base64_decode(trim(substr($auth, 6)), true);
        if (is_string($pair) && strpos($pair, ':') !== false) {
            $user = (string) substr($pair, 0, strpos($pair, ':'));
            $password = (string) substr($pair, strpos($pair, ':') + 1);
        }
    }
}
if (strlen($key) > 200 || strlen($user) > 200 || strlen($password) > 400) {
    banfeed_say(403, "forbidden\n");
}

$format = strtolower(preg_replace('/[^a-z]/i', '', (string) ($_GET['f'] ?? ($_GET['format'] ?? ''))));
$family = strtolower(preg_replace('/[^a-z0-9]/i', '', (string) ($_GET['family'] ?? '')));
$md5 = isset($_GET['md5']) && (string) $_GET['md5'] !== '0';

[$status, $body] = isemon_call('/api/banfeed', 'POST', [
    'key'    => $key,
    'user'   => $user,
    'password' => $password,
    'format' => $format,
    'family' => $family,
    'md5'    => $md5,
], 20.0);
if ($status === 0) {
    banfeed_say(503, "the daemon is not answering\n", ['Retry-After: 60']);
}
$data = json_decode($body, true);
if (!is_array($data) || !isset($data['body'])) {
    banfeed_say($status >= 400 ? $status : 502, "something went wrong\n");
}
$code = (int) ($data['status'] ?? $status);
if ($code === 401) {
    /* A user name and a password are asked for: asked for the way a client
       that only sends its credentials when challenged expects to be asked. */
    header('WWW-Authenticate: Basic realm="isemon ban list"');
}
$type = ((string) ($data['type'] ?? '') === 'application/json')
    ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8';
http_response_code($code > 0 ? $code : 502);
header('Content-Type: ' . $type);
$text = (string) $data['body'];
header('Content-Length: ' . strlen($text));
if ($method !== 'HEAD') {
    echo $text;
}
