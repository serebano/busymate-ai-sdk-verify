<?php
declare(strict_types=1);
// php snippets/php/test_vectors.php  (exit 1 on any failure)
require __DIR__ . '/BusymateVerify.php';

$V = json_decode(file_get_contents(__DIR__ . '/../../vectors/actor-v3.json'), true);
$fail = 0; $n = 0;
foreach ($V['cases'] as $case) {
    $n++;
    $seen = [];
    $err = null;
    foreach ($case['calls'] as $call) {
        $cfg = array_merge($V['config'], $case['options'] ?? [], $call['options'] ?? []);
        $o = ['audience' => $cfg['audience'], 'tenant_id' => $cfg['tenant_id'], 'connector_id' => $cfg['connector_id'],
              'jwks' => $V['jwks'], 'now' => $V['now'], 'seen' => &$seen];
        if (!empty($cfg['idp'])) $o['idp'] = $cfg['idp'];
        if (!empty($cfg['tool'])) $o['tool'] = $cfg['tool'];
        $exp = $call['expect'];
        try {
            $a = BusymateVerify::verify($call['headers'], $o);
            if (!$exp['ok']) { $err = "expected {$exp['reason']}, got ok"; break; }
            $e = $exp['actor'];
            $want = ['sub' => $e['sub'], 'idp' => $e['idp'], 'confirmed' => $e['confirmed'], 'tool' => $e['tool'], 'jti' => $e['jti'], 'support_session_id' => $e['supportSessionId'] ?? null,
                'host_account' => $e['hostAccount'] ?? null, 'host_env' => $e['hostEnv'] ?? null, 'host_user' => $e['hostUser'] ?? null];
            if ($a !== $want) { $err = 'actor differs: ' . json_encode($a); break; }
        } catch (BusymateActorError $x) {
            if ($exp['ok'] || $x->reason !== $exp['reason']) { $err = "expected " . ($exp['ok'] ? 'ok' : $exp['reason']) . ", got {$x->reason}"; break; }
        }
        unset($o);
    }
    echo ($err === null ? "ok   " : "FAIL ") . $case['name'] . ($err ? " ($err)" : '') . "\n";
    if ($err !== null) $fail++;
}
// Replay window: the jti stays remembered until exp + skew, so a replay at exp+5s is refused.
$n++;
$rc = null; foreach ($V['cases'] as $c) if ($c['name'] === 'replay') $rc = $c['calls'][0];
$exp = json_decode(base64_decode(strtr(explode('.', $rc['headers']['X-Bmai-Actor'])[1], '-_', '+/')), true)['exp'];
$seen = []; $err = null;
$ro = fn(int $now) => ['audience' => $V['config']['audience'], 'tenant_id' => $V['config']['tenant_id'], 'connector_id' => $V['config']['connector_id'], 'jwks' => $V['jwks'], 'now' => $now];
try {
    $o = $ro($exp - 5); $o['seen'] = &$seen; BusymateVerify::verify($rc['headers'], $o); unset($o);
    $o = $ro($exp + 5); $o['seen'] = &$seen; BusymateVerify::verify($rc['headers'], $o); unset($o);
    $err = 'replay at exp+5 accepted';
} catch (BusymateActorError $x) { if ($x->reason !== 'replay') $err = "expected replay, got {$x->reason}"; }
echo ($err === null ? "ok   " : "FAIL ") . "replay_at_exp_plus_5" . ($err ? " ($err)" : '') . "\n";
if ($err !== null) $fail++;

// Capacity: a full store of live entries refuses a new jti (replay_cache_capacity), never evicts one.
$n++;
$hdr = function (string $name) use ($V) { foreach ($V['cases'] as $c) if ($c['name'] === $name) return $c['calls'][0]['headers']; };
$seen = []; $err = null; $got = [];
foreach (['valid_x_header', 'valid_confirmed', 'valid_x_header'] as $name) {
    $o = ['audience' => $V['config']['audience'], 'tenant_id' => $V['config']['tenant_id'], 'connector_id' => $V['config']['connector_id'],
          'jwks' => $V['jwks'], 'now' => $V['now'], 'max_seen' => 1];
    $o['seen'] = &$seen;
    try { BusymateVerify::verify($hdr($name), $o); $got[] = 'ok'; } catch (BusymateActorError $x) { $got[] = $x->reason; }
    unset($o);
}
if ($got !== ['ok', 'replay_cache_capacity', 'replay']) $err = 'got ' . implode(',', $got);
echo ($err === null ? "ok   " : "FAIL ") . "replay_cache_capacity" . ($err ? " ($err)" : '') . "\n";
if ($err !== null) $fail++;

try { BusymateVerify::requireConfirmed(['confirmed' => false]); $fail++; echo "FAIL requireConfirmed\n"; } catch (BusymateActorError $x) { if ($x->reason !== 'confirmation_required') $fail++; }
echo "$n cases, $fail failed\n";
exit($fail ? 1 : 0);
