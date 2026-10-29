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
            $want = ['sub' => $e['sub'], 'idp' => $e['idp'], 'confirmed' => $e['confirmed'], 'tool' => $e['tool'], 'jti' => $e['jti'], 'support_session_id' => $e['supportSessionId'] ?? null];
            if ($a !== $want) { $err = 'actor differs: ' . json_encode($a); break; }
        } catch (BusymateActorError $x) {
            if ($exp['ok'] || $x->reason !== $exp['reason']) { $err = "expected " . ($exp['ok'] ? 'ok' : $exp['reason']) . ", got {$x->reason}"; break; }
        }
        unset($o);
    }
    echo ($err === null ? "ok   " : "FAIL ") . $case['name'] . ($err ? " ($err)" : '') . "\n";
    if ($err !== null) $fail++;
}
try { BusymateVerify::requireConfirmed(['confirmed' => false]); $fail++; echo "FAIL requireConfirmed\n"; } catch (BusymateActorError $x) { if ($x->reason !== 'confirmation_required') $fail++; }
echo "$n cases, $fail failed\n";
exit($fail ? 1 : 0);
