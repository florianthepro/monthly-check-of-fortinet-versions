<?php
declare(strict_types=1);
const DATA = __DIR__ . '/data', REPORTS = DATA . '/reports', ATTRS = DATA . '/attributes', CVES = DATA . '/cves';
foreach ([DATA, REPORTS, ATTRS, CVES] as $d)
    if (!is_dir($d))
        @mkdir($d, 0770, true);
function cfg(): array
{
    $x = json_decode((string) @file_get_contents(__DIR__ . '/info.json'), true);
    if (!is_array($x))
        die('info.json fehlt oder ist ungültig');
    foreach ($x['systems'] ?? [] as $index => $system) {
        $product = (string)($system['product'] ?? '');
        if ($product === '') {
            $systemId = (string)($system['id'] ?? '');
            if (strpos($systemId, '1.') === 0) $product = 'fortios';
            elseif ($systemId === '2.1' || $systemId === '2.2') $product = 'fortimanager';
            elseif ($systemId === '2.3') $product = 'fortianalyzer';
            if ($product !== '') $x['systems'][$index]['product'] = $product;
        }
        if ($product === '' || !isset($x['products'][$product])) {
            die('info.json: ungültiges oder fehlendes product bei System ' . htmlspecialchars((string)($system['id'] ?? $index)));
        }
    }
    return $x;
}
function out(array $x, int $s = 200): void
{
    http_response_code($s);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($x, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}
function id(string $x): string
{
    return preg_replace('/[^a-zA-Z0-9._-]/', '', $x) ?? '';
}
function readj(string $p): array
{
    $x = json_decode((string) @file_get_contents($p), true);
    return is_array($x) ? $x : [];
}
function writej(string $p, array $x): void
{
    $t = $p . '.tmp';
    if (file_put_contents($t, json_encode($x, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX) === false || !rename($t, $p))
        throw new RuntimeException('Speichern fehlgeschlagen');
}
function fetchj(string $url, string $key, int $timeout): array
{
    $h = ['Accept: application/json', 'User-Agent: Monthly-Fortinet-Check/3'];
    if ($key !== '')
        $h[] = 'apiKey: ' . $key;
    if (function_exists('curl_init')) {
        $c = curl_init($url);
        curl_setopt_array($c, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => $timeout, CURLOPT_HTTPHEADER => $h]);
        $b = curl_exec($c);
        $n = (int) curl_getinfo($c, CURLINFO_RESPONSE_CODE);
        $e = curl_error($c);
        if ($b === false || $n < 200 || $n > 299)
            throw new RuntimeException($e ?: 'API HTTP ' . $n);
    } else {
        $b = @file_get_contents($url, false, stream_context_create(['http' => ['header' => implode("\r\n", $h), 'timeout' => $timeout]]));
        if ($b === false)
            throw new RuntimeException('API nicht erreichbar');
    }
    $j = json_decode($b, true);
    if (!is_array($j))
        throw new RuntimeException('Ungültige API-Antwort');
    return $j;
}
function productParts(array $product): array
{
    return array_values(array_unique(array_filter(array_map('strval', $product['parts'] ?? [$product['part'] ?? 'a']))));
}
function productNames(string $id, array $product): array
{
    return array_values(array_unique(array_merge([$id], array_filter(array_map('strval', $product['aliases'] ?? [])))));
}
function stableVersion(string $version): bool
{
    return preg_match('/^\d+(?:\.\d+){1,3}$/', $version) === 1 && preg_match('/(?:alpha|beta|preview|rc|build|dev|test)/i', $version) !== 1;
}
function ver(string $a, string $b): int
{
    return version_compare(preg_replace('/[^0-9.].*/', '', $a), preg_replace('/[^0-9.].*/', '', $b));
}
function branch(string $v): string
{
    $p = explode('.', preg_replace('/[^0-9.].*/', '', $v));
    return ($p[0] ?? '0') . '.' . ($p[1] ?? '0');
}
function nextPatch(string $v): string
{
    $p = array_map('intval', explode('.', preg_replace('/[^0-9.].*/', '', $v)));
    while (count($p) < 3)
        $p[] = 0;
    $p[2]++;
    return implode('.', array_slice($p, 0, 3));
}
function hit(string $v, array $m): bool
{
    $parts = explode(':', (string) ($m['criteria'] ?? ''));
    $exact = $parts[5] ?? '*';
    if ($exact !== '*' && $exact !== '-' && ver($v, $exact) !== 0)
        return false;
    if (isset($m['versionStartIncluding']) && ver($v, (string) $m['versionStartIncluding']) < 0)
        return false;
    if (isset($m['versionStartExcluding']) && ver($v, (string) $m['versionStartExcluding']) <= 0)
        return false;
    if (isset($m['versionEndIncluding']) && ver($v, (string) $m['versionEndIncluding']) > 0)
        return false;
    if (isset($m['versionEndExcluding']) && ver($v, (string) $m['versionEndExcluding']) >= 0)
        return false;
    return true;
}
function desc(array $c): string
{
    foreach ($c['descriptions'] ?? [] as $d)
        if (($d['lang'] ?? '') === 'en')
            return (string) ($d['value'] ?? '');
    return (string) ($c['descriptions'][0]['value'] ?? '');
}
function comps(string $t, string $label): array
{
    $map = ['ssl-vpn' => 'SSL-VPN', 'ssl vpn' => 'SSL-VPN', 'saml' => 'SAML', 'api' => 'API', 'web interface' => 'Web Interface', 'administrative interface' => 'Administrative Interface', 'cli' => 'CLI', 'proxy' => 'Proxy', 'fortiguard' => 'FortiGuard', 'ipsec' => 'IPsec', 'daemon' => 'Systemdienst', 'plugin' => 'Plugin'];
    $r = [];
    $t = strtolower($t);
    foreach ($map as $needle => $name)
        if (strpos($t, $needle) !== false)
            $r[$name] = true;
    return array_keys($r ?: [$label . ' allgemein' => true]);
}
function syncPaths(string $pid): array
{
    $safe = id($pid);
    return [DATA . '/sync-' . $safe . '.json', DATA . '/sync-' . $safe . '-cves.jsonl', DATA . '/sync-' . $safe . '-versions.txt'];
}
function syncMissing(array $c): array
{
    $versions = readj(DATA . '/version.json');
    $missing = [];
    foreach ($c['products'] as $pid => $product) {
        $cv = readj(DATA . '/cves/' . id($pid) . '.json');
        if (!$cv || empty($versions['products'][$pid]['versions']))
            $missing[] = $pid;
    }
    return $missing;
}
function syncStatus(array $c): array
{
    $missing = syncMissing($c);
    return ['ready' => !$missing, 'missing' => $missing, 'total' => count($c['products'])];
}
function appendJsonLines(string $path, array $items): void
{
    if (!$items)
        return;
    $h = fopen($path, 'ab');
    if (!$h)
        throw new RuntimeException('Temporäre Synchronisationsdatei kann nicht geöffnet werden');
    foreach ($items as $item)
        fwrite($h, json_encode($item, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
    fclose($h);
}
function finalizeProduct(array $c, string $pid, array $state, string $cveTmp, string $versionTmp): array
{
    $product = $c['products'][$pid];
    $parts = productParts($product);
    $names = productNames($pid, $product);
    $byId = [];
    if (is_file($cveTmp)) {
        $h = fopen($cveTmp, 'rb');
        while (($line = fgets($h)) !== false) {
            $w = json_decode($line, true);
            $cid = (string) ($w['cve']['id'] ?? '');
            if ($cid !== '')
                $byId[$cid] = $w;
        }
        fclose($h);
    }
    $cves = [];
    $boundaryVersions = [];
    foreach ($byId as $w) {
        $x = $w['cve'] ?? [];
        $matches = [];
        foreach ($x['configurations'] ?? [] as $co)
            foreach ($co['nodes'] ?? [] as $node)
                foreach ($node['cpeMatch'] ?? [] as $m) {
                    $z = explode(':', (string) ($m['criteria'] ?? ''));
                    if (!($m['vulnerable'] ?? false) || ($z[3] ?? '') !== 'fortinet' || !in_array($z[4] ?? '', $names, true) || !in_array($z[2] ?? '', $parts, true))
                        continue;
                    $matches[] = $m;
                    $exact = $z[5] ?? '*';
                    if (stableVersion($exact))
                        $boundaryVersions[$exact] = true;
                    foreach (['versionStartIncluding', 'versionStartExcluding', 'versionEndIncluding', 'versionEndExcluding'] as $k)
                        if (isset($m[$k]) && stableVersion((string) $m[$k]))
                            $boundaryVersions[(string) $m[$k]] = true;
                    if (isset($m['versionEndExcluding']) && stableVersion((string) $m['versionEndExcluding']))
                        $boundaryVersions[(string) $m['versionEndExcluding']] = true;
                    if (isset($m['versionEndIncluding']))
                        $boundaryVersions[nextPatch((string) $m['versionEndIncluding'])] = true;
                }
        if (!$matches)
            continue;
        $cves[] = ['id' => (string) ($x['id'] ?? ''), 'published' => (string) ($x['published'] ?? ''), 'url' => (string) $c['api']['cve_record_url'] . rawurlencode((string) ($x['id'] ?? '')), 'components' => comps(desc($x), (string) $product['label']), 'matches' => $matches];
    }
    $versions = [];
    if (is_file($versionTmp))
        foreach (file($versionTmp, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $v)
            if (stableVersion(trim($v)))
                $versions[trim($v)] = true;
    foreach ($boundaryVersions as $v => $_)
        $versions[$v] = true;
    $versions = array_keys($versions);
    usort($versions, 'ver');
    $latest = $versions ? end($versions) : '';
    $versionFile = readj(DATA . '/version.json');
    $versionFile['updated_at'] = date(DATE_ATOM);
    $versionFile['products'][$pid] = ['label' => $product['label'], 'latest' => $latest, 'versions' => $versions];
    writej(DATA . '/version.json', $versionFile);
    writej(DATA . '/cves/' . id($pid) . '.json', ['product' => $pid, 'label' => $product['label'], 'synced_at' => date(DATE_ATOM), 'cves' => $cves]);
    [$stateFile] = syncPaths($pid);
    @unlink($stateFile);
    @unlink($cveTmp);
    @unlink($versionTmp);
    return ['done' => true, 'product' => $pid, 'cves' => count($cves), 'versions' => count($versions), 'latest' => $latest];
}
function apiRequestPause(bool $hasKey): void
{
    $file = DATA . '/api-last-request.txt';
    $gap = $hasKey ? 0.7 : 6.5;
    $last = is_file($file) ? (float) file_get_contents($file) : 0.0;
    $wait = $gap - (microtime(true) - $last);
    if ($wait > 0)
        usleep((int) ($wait * 1000000));
    file_put_contents($file, (string) microtime(true), LOCK_EX);
}
function syncProbe(array $c, string $pid): array
{
    $product = $c['products'][$pid] ?? null;
    if (!is_array($product))
        throw new RuntimeException('Produkt unbekannt');
    $cachePath = DATA . '/cves/' . id($pid) . '.json';
    $cache = readj($cachePath);
    $versions = readj(DATA . '/version.json');
    if (!$cache || empty($versions['products'][$pid]['versions']))
        return ['product' => $pid, 'stale' => true, 'reason' => 'missing'];
    $api = $c['api'];
    $end = new DateTimeImmutable('now', new DateTimeZone('UTC'));
    $stored = strtotime((string) ($cache['synced_at'] ?? $versions['updated_at'] ?? '')) ?: $end->modify('-110 days')->getTimestamp();
    $minimum = $end->modify('-110 days')->getTimestamp();
    $start = (new DateTimeImmutable('@' . max($stored, $minimum)))->setTimezone(new DateTimeZone('UTC'));
    $date = ['lastModStartDate' => $start->format('Y-m-d\\TH:i:s.000'), 'lastModEndDate' => $end->format('Y-m-d\\TH:i:s.000'), 'resultsPerPage' => 1];
    $timeout = min(40, max(10, (int) ($api['timeout_seconds'] ?? 30)));
    foreach (productParts($product) as $part)
        foreach (productNames($pid, $product) as $name) {
            $cveQ = $date + ['virtualMatchString' => 'cpe:2.3:' . $part . ':fortinet:' . $name];
            apiRequestPause((string) ($api['key'] ?? '') !== '');
            $cve = fetchj((string) $api['cves_url'] . '?' . http_build_query($cveQ), (string) ($api['key'] ?? ''), $timeout);
            $cpeQ = $date + ['cpeMatchString' => 'cpe:2.3:' . $part . ':fortinet:' . $name . ':*:*:*:*:*:*:*:*'];
            apiRequestPause((string) ($api['key'] ?? '') !== '');
            $cpe = fetchj((string) ($api['cpes_url'] ?? 'https://services.nvd.nist.gov/rest/json/cpes/2.0') . '?' . http_build_query($cpeQ), (string) ($api['key'] ?? ''), $timeout);
            if ((int) ($cve['totalResults'] ?? 0) > 0 || (int) ($cpe['totalResults'] ?? 0) > 0) {
                @unlink($cachePath);
                unset($versions['products'][$pid]);
                writej(DATA . '/version.json', $versions);
                return ['product' => $pid, 'stale' => true, 'reason' => 'remote-change'];
            }
        }
    return ['product' => $pid, 'stale' => false, 'checked_at' => date(DATE_ATOM)];
}
function syncStep(array $c, string $pid): array
{
    $product = $c['products'][$pid] ?? null;
    if (!is_array($product))
        throw new RuntimeException('Produkt unbekannt');
    if (!is_dir(DATA . '/cves') && !mkdir(DATA . '/cves', 0770, true) && !is_dir(DATA . '/cves'))
        throw new RuntimeException('data/cves kann nicht erstellt werden');
    [$stateFile, $cveTmp, $versionTmp] = syncPaths($pid);
    $state = readj($stateFile);
    if (!$state) {
        @unlink($cveTmp);
        @unlink($versionTmp);
        $combos = [];
        foreach (productParts($product) as $part)
            foreach (productNames($pid, $product) as $name)
                $combos[] = ['part' => $part, 'name' => $name];
        $state = ['phase' => 'cves', 'combo' => 0, 'index' => 0, 'total' => null, 'combos' => $combos, 'pages' => 0];
        writej($stateFile, $state);
    }
    $api = $c['api'];
    $timeout = min(45, max(10, (int) ($api['timeout_seconds'] ?? 35)));
    $pageSize = max(20, min(2000, (int) ($api['page_size'] ?? 100)));
    if ($state['phase'] === 'cves') {
        if ($state['combo'] >= count($state['combos'])) {
            $state = ['phase' => 'versions', 'combo' => 0, 'index' => 0, 'total' => null, 'combos' => $state['combos'], 'pages' => $state['pages']];
            writej($stateFile, $state);
            return ['done' => false, 'product' => $pid, 'phase' => 'versions', 'message' => 'CVE-Daten vollständig, Versionskatalog wird geladen', 'progress' => 70];
        }
        $combo = $state['combos'][$state['combo']];
        $q = ['virtualMatchString' => 'cpe:2.3:' . $combo['part'] . ':fortinet:' . $combo['name'], 'startIndex' => $state['index'], 'resultsPerPage' => $pageSize];
        $url = (string) $api['cves_url'] . '?' . http_build_query($q);
        apiRequestPause((string) ($api['key'] ?? '') !== '');
        $j = fetchj($url, (string) ($api['key'] ?? ''), $timeout);
        appendJsonLines($cveTmp, $j['vulnerabilities'] ?? []);
        $state['total'] = (int) ($j['totalResults'] ?? 0);
        $state['index'] += (int) ($j['resultsPerPage'] ?? count($j['vulnerabilities'] ?? []));
        $state['pages']++;
        if ($state['index'] >= $state['total'] || empty($j['vulnerabilities'])) {
            $state['combo']++;
            $state['index'] = 0;
            $state['total'] = null;
        }
        writej($stateFile, $state);
        $comboProgress = count($state['combos']) ? $state['combo'] / count($state['combos']) : 1;
        return ['done' => false, 'product' => $pid, 'phase' => 'cves', 'message' => 'CVE-Seite ' . $state['pages'] . ' gespeichert', 'progress' => min(69, (int) (5 + $comboProgress * 64)), 'url' => $url];
    }
    if ($state['combo'] >= count($state['combos']))
        return finalizeProduct($c, $pid, $state, $cveTmp, $versionTmp);
    $combo = $state['combos'][$state['combo']];
    $base = (string) ($api['cpes_url'] ?? 'https://services.nvd.nist.gov/rest/json/cpes/2.0');
    $criteria = 'cpe:2.3:' . $combo['part'] . ':fortinet:' . $combo['name'] . ':*:*:*:*:*:*:*:*';
    $q = ['cpeMatchString' => $criteria, 'startIndex' => $state['index'], 'resultsPerPage' => $pageSize];
    $url = $base . '?' . http_build_query($q);
    apiRequestPause((string) ($api['key'] ?? '') !== '');
    $j = fetchj($url, (string) ($api['key'] ?? ''), $timeout);
    $lines = [];
    foreach ($j['products'] ?? [] as $entry) {
        $name = (string) ($entry['cpe']['cpeName'] ?? '');
        $parts = explode(':', $name);
        $v = $parts[5] ?? '';
        if (stableVersion($v))
            $lines[$v] = true;
    }
    if ($lines)
        file_put_contents($versionTmp, implode("\n", array_keys($lines)) . "\n", FILE_APPEND | LOCK_EX);
    $state['total'] = (int) ($j['totalResults'] ?? 0);
    $state['index'] += (int) ($j['resultsPerPage'] ?? count($j['products'] ?? []));
    $state['pages']++;
    if ($state['index'] >= $state['total'] || empty($j['products'])) {
        $state['combo']++;
        $state['index'] = 0;
        $state['total'] = null;
    }
    writej($stateFile, $state);
    $comboProgress = count($state['combos']) ? $state['combo'] / count($state['combos']) : 1;
    return ['done' => false, 'product' => $pid, 'phase' => 'versions', 'message' => 'Versionsseite gespeichert', 'progress' => min(99, (int) (70 + $comboProgress * 29)), 'url' => $url];
}
function scan(array $c, string $pid, string $version = ''): array
{
    $product = $c['products'][$pid] ?? null;
    if (!is_array($product))
        throw new RuntimeException('Produkt unbekannt');
    $cache = readj(DATA . '/cves/' . id($pid) . '.json');
    $versionFile = readj(DATA . '/version.json');
    if (!$cache || empty($versionFile['products'][$pid]['versions']))
        throw new RuntimeException('Lokale Produktdaten fehlen. Seite neu laden, um die Synchronisation zu starten.');
    $cves = $cache['cves'] ?? [];
    $versions = $versionFile['products'][$pid]['versions'];
    $lastRed = [];
    $affectedMap = [];
    foreach ($versions as $v) {
        $hits = [];
        foreach ($cves as $cv)
            foreach ($cv['matches'] ?? [] as $m)
                if (hit($v, $m)) {
                    $hits[] = $cv['id'];
                    break;
                }
        $affectedMap[$v] = $hits;
        if ($hits)
            $lastRed[branch($v)] = $v;
    }
    $rows = [];
    foreach ($versions as $v) {
        $hits = $affectedMap[$v] ?? [];
        $b = branch($v);
        $status = $hits ? 'red' : (isset($lastRed[$b]) && ver($v, $lastRed[$b]) > 0 ? 'green' : 'yellow');
        $rows[] = ['version' => $v, 'status' => $status];
    }
    $affected = [];
    if ($version !== '')
        foreach ($cves as $cv)
            foreach ($cv['matches'] ?? [] as $m)
                if (hit($version, $m)) {
                    $affected[] = $cv;
                    break;
                }
    $status = $affected ? 'red' : 'green';
    foreach ($rows as $r)
        if ($r['version'] === $version) {
            $status = $r['status'];
            break;
        }
    return ['product' => $pid, 'label' => $product['label'], 'latest' => $versionFile['products'][$pid]['latest'] ?? '', 'synced_at' => $cache['synced_at'] ?? '', 'rows' => $rows, 'checked_version' => $version, 'status' => $status, 'affected' => $affected, 'received' => count($cves), 'relevant' => count($affected), 'pages' => 0, 'query_url' => 'local:data/cves/' . id($pid) . '.json', 'source_links' => []];
}
$c = cfg();
$a = $_GET['_action'] ?? '';
if ($a) {
    try {
        if ($a === 'sync_status') {
            out(syncStatus($c));
        }
        if ($a === 'sync_probe') {
            out(syncProbe($c, id((string) ($_GET['product'] ?? ''))));
        }
        if ($a === 'sync_step') {
            out(syncStep($c, id((string) ($_GET['product'] ?? ''))));
        }
        if ($a === 'scan') {
            out(scan($c, id((string) ($_GET['product'] ?? '')), trim((string) ($_GET['version'] ?? ''))));
        }
        if ($a === 'list') {
            $r = [];
            foreach (glob(REPORTS . '/*.json') ?: [] as $f) {
                $x = readj($f);
                $r[] = ['id' => basename($f, '.json'), 'name' => $x['name'] ?? '', 'report_date' => $x['report_date'] ?? ''];
            }
            usort($r, fn($x, $y) => strcmp($y['report_date'], $x['report_date']));
            out(['reports' => $r]);
        }
        if ($a === 'report') {
            $x = readj(REPORTS . '/' . id((string) $_GET['id']) . '.json');
            out($x ? ['report' => $x] : ['error' => 'Nicht gefunden'], $x ? 200 : 404);
        }
        if ($a === 'attrs') {
            $rid = id((string) $_GET['report']);
            $r = [];
            foreach (glob(ATTRS . '/' . $rid . '-*.json') ?: [] as $f) {
                $x = readj($f);
                $r[] = ['id' => basename($f, '.json'), 'name' => $x['name'] ?? '', 'date' => $x['date'] ?? ''];
            }
            out(['attributes' => $r]);
        }
        if ($a === 'attr') {
            $x = readj(ATTRS . '/' . id((string) $_GET['id']) . '.json');
            out($x ? ['attribute' => $x] : ['error' => 'Nicht gefunden'], $x ? 200 : 404);
        }
        if ($a === 'save') {
            if ($_SERVER['REQUEST_METHOD'] !== 'POST')
                out(['error' => 'POST benötigt'], 405);
            $b = json_decode((string) file_get_contents('php://input'), true);
            if (!is_array($b))
                out(['error' => 'Ungültig'], 400);
            $mode = $b['mode'] ?? 'report';
            if ($mode === 'report') {
                $rid = date('Ymd-His') . '-' . substr(bin2hex(random_bytes(6)), 0, 8);
                $now = date(DATE_ATOM);
                $r = ['id' => $rid, 'name' => trim((string) $b['name']), 'report_date' => $now, 'system_attribute' => ['id' => 'system', 'name' => 'Systemreferenzpunkt', 'date' => null, 'values' => $b['entries'] ?? []], 'snapshots' => $b['snapshots'] ?? [], 'source_links' => $b['source_links'] ?? []];
                writej(REPORTS . '/' . $rid . '.json', $r);
                out(['report' => $rid]);
            }
            $rid = id((string) $b['report']);
            $aid = $rid . '-' . date('YmdHis') . '-' . substr(bin2hex(random_bytes(4)), 0, 6);
            writej(ATTRS . '/' . $aid . '.json', ['id' => $aid, 'report' => $rid, 'name' => trim((string) $b['name']), 'date' => date(DATE_ATOM), 'values' => $b['values'] ?? []]);
            out(['attribute' => $aid]);
        }
        out(['error' => 'Aktion unbekannt'], 404);
    } catch (Throwable $e) {
        out(['error' => $e->getMessage()], 502);
    }
}
$page = in_array($_GET['_page'] ?? '', ['create', 'view', 'products'], true) ? $_GET['_page'] : 'create';
$pub = $c;
$pub['api']['key'] = $c['api']['key'] !== '';
?>
<!doctype html>
<html lang="de">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title><?= htmlspecialchars($c['title']) ?></title>
    <style>
        :root {
            color-scheme: light dark;
            --bg: #f7f7f7;
            --panel: #fff;
            --text: #202124;
            --muted: #666;
            --line: #d6d6d6;
            --blue: #1769aa;
            --red: #b3261e;
            --yellow: #8a6200;
            --green: #137333
        }

        * {
            box-sizing: border-box
        }

        body {
            margin: 0;
            background: var(--bg);
            color: var(--text);
            font: 15px/1.45 Arial, sans-serif
        }

        header {
            border-bottom: 1px solid var(--line);
            background: var(--panel)
        }

        header>div {
            padding: 16px 28px;
            display: flex;
            gap: 28px;
            align-items: center
        }

        .title {
            font-size: 20px;
            font-weight: bold;
            flex: 1
        }

        nav a {
            color: var(--text);
            text-decoration: none;
            margin-left: 20px
        }

        nav a.on {
            font-weight: bold;
            color: var(--blue)
        }

        main {
            padding: 24px 28px;
            width: 100%
        }

        .panel {
            background: var(--panel);
            border: 1px solid var(--line);
            padding: 22px
        }

        .top {
            display: flex;
            gap: 16px;
            align-items: flex-start
        }

        .top h1,
        .top h2 {
            margin: 0
        }

        .grow {
            flex: 1
        }

        .muted {
            color: var(--muted)
        }

        label {
            display: block;
            font-weight: bold;
            margin: 16px 0 5px
        }

        input,
        select,
        textarea,
        button {
            font: inherit;
            color: inherit
        }

        input,
        select,
        textarea {
            background: var(--panel);
            border: 1px solid var(--line);
            padding: 9px;
            width: 100%
        }

        textarea {
            min-height: 190px
        }

        button {
            padding: 9px 15px;
            border: 1px solid var(--line);
            background: var(--panel);
            cursor: pointer
        }

        .primary {
            background: var(--blue);
            border-color: var(--blue);
            color: #fff
        }

        .actions {
            display: flex;
            gap: 8px;
            justify-content: flex-end;
            margin-top: 18px
        }

        .bar {
            height: 9px;
            background: #ddd;
            margin: 16px 0;
            overflow: hidden
        }

        .bar i {
            display: block;
            height: 100%;
            width: 0;
            background: var(--blue);
            transition: width .5s
        }

        .live {
            border: 1px solid var(--line);
            padding: 12px;
            min-height: 110px;
            white-space: pre-wrap;
            font: 13px/1.5 monospace
        }

        .hidden {
            display: none
        }

        .status {
            font-weight: bold
        }

        .red {
            color: var(--red)
        }

        .yellow {
            color: var(--yellow)
        }

        .green {
            color: var(--green)
        }

        table {
            width: 100%;
            border-collapse: collapse
        }

        th,
        td {
            border: 1px solid var(--line);
            padding: 9px;
            vertical-align: top
        }

        th {
            background: color-mix(in srgb, var(--panel) 85%, var(--line))
        }

        .versions td {
            width: 33.333%
        }

        .version {
            display: block;
            padding: 5px 7px;
            margin: 2px 0
        }

        .selected {
            outline: 2px solid var(--blue)
        }

        .cards {
            display: grid;
            grid-template-columns: 280px 1fr;
            gap: 20px
        }

        .list button {
            display: block;
            width: 100%;
            text-align: left;
            margin-bottom: 6px
        }

        .screen {
            position: fixed;
            inset: 0;
            background: var(--bg);
            z-index: 20;
            padding: 20px;
            overflow: auto
        }

        .report-grid {
            display: grid;
            grid-template-columns: 240px 1fr;
            gap: 20px
        }

        .entry {
            border-bottom: 1px solid var(--line);
            padding: 13px 0
        }

        .entry:last-child {
            border: 0
        }

        .refbox {
            border: 1px solid var(--line);
            padding: 12px;
            margin: 8px 0
        }

        .input-list {
            border-top: 1px solid var(--line)
        }

        .input-row {
            display: grid;
            grid-template-columns: minmax(260px, 1fr) minmax(180px, 320px);
            gap: 20px;
            align-items: center;
            padding: 12px 0;
            border-bottom: 1px solid var(--line)
        }

        .input-row small {
            display: block
        }

        .scan-row,
        .decision-row {
            border-bottom: 1px solid var(--line);
            padding: 16px 0
        }

        .scan-row pre {
            white-space: pre-wrap;
            margin: 8px 0
        }

        .scan-state {
            margin-left: auto
        }

        .actions button:disabled {
            opacity: .45;
            cursor: not-allowed
        }

        .report-page {
            padding: 24px 28px
        }

        .report-head {
            display: flex;
            justify-content: space-between;
            gap: 20px;
            align-items: center;
            position: sticky;
            top: 0;
            background: var(--bg);
            padding: 10px 0;
            border-bottom: 1px solid var(--line);
            z-index: 3
        }

        .report-box {
            width: 100%;
            min-height: 65vh;
            border: 1px solid var(--line);
            background: var(--panel);
            padding: 22px;
            font: 15px/1.65 ui-monospace, SFMono-Regular, Consolas, monospace;
            white-space: normal
        }

        .report-line {
            padding: 0 0 18px;
            margin: 0 0 18px;
            border-bottom: 1px solid var(--line)
        }

        .report-line:last-child {
            border-bottom: 0
        }

        .report-static {
            user-select: text
        }

        .report-decision {
            margin: 5px 0
        }

        .editable-token,
        .editable-choice {
            background: color-mix(in srgb, var(--yellow) 22%, var(--panel));
            border: 1px solid var(--yellow);
            border-radius: 3px;
            padding: 2px 5px
        }

        .editable-token {
            display: inline-block;
            min-width: 44px;
            outline: none
        }

        .editable-token:focus,
        .editable-choice:focus {
            outline: 2px solid var(--blue);
            outline-offset: 1px
        }

        .editable-choice {
            width: auto
        }

        .report-links {
            margin-top: 5px
        }

        .report-links a {
            margin-right: 10px
        }

        .report-buttons {
            display: flex;
            gap: 8px;
            flex-wrap: wrap
        }

        .report-text {
            font-size: 16px;
            line-height: 1.65
        }

        .text-line {
            padding: 16px 0;
            border-bottom: 1px solid var(--line)
        }

        .editable {
            background: color-mix(in srgb, var(--yellow) 18%, transparent);
            padding: 2px 5px;
            outline: 1px dashed var(--yellow)
        }

        .static {
            margin-bottom: 5px
        }

        .overlay {
            position: fixed;
            inset: 0;
            background: #0009;
            display: grid;
            place-items: center;
            z-index: 20
        }

        .dialog {
            background: var(--panel);
            border: 1px solid var(--line);
            padding: 22px;
            width: min(480px, calc(100% - 30px))
        }

        .report-textbox {
            width: 100%;
            min-height: 70vh;
            border: 1px solid var(--line);
            background: var(--panel);
            padding: 24px;
            font: 15px/1.55 Arial, sans-serif;
            white-space: normal;
            cursor: text
        }

        .report-main-title {
            font-weight: bold;
            margin-bottom: 42px
        }

        .report-section-title {
            font-weight: bold;
            margin: 0 0 22px
        }

        .report-intro {
            margin-bottom: 22px
        }

        .report-entry-text {
            margin-bottom: 22px
        }

        .report-entry-text+.report-section-title {
            margin-top: 39px
        }

        .automatic-report-part {
            display: inline;
            color: var(--text)
        }

        .editable-report-part {
            display: inline;
            padding: 2px 4px;
            border: 0;
            border-radius: 2px;
            background: color-mix(in srgb, var(--yellow) 22%, var(--panel));
            color: var(--text);
            font: inherit;
            text-align: left;
            cursor: pointer;
            box-shadow: inset 0 -1px 0 var(--yellow)
        }

        .editable-report-part:hover,
        .editable-report-part:focus {
            outline: 2px solid var(--yellow);
            outline-offset: 1px
        }

        .report-buttons {
            display: flex;
            gap: 8px;
            flex-wrap: wrap
        }

        .todo-device {
            display: grid;
            grid-template-columns: 72px minmax(0, 1fr) minmax(210px, 300px);
            gap: 18px;
            align-items: start;
            padding: 18px 0;
            border-bottom: 1px solid var(--line)
        }

        .todo-device:first-child {
            border-top: 1px solid var(--line)
        }

        .todo-number {
            font-weight: bold;
            font-size: 16px;
            padding-top: 2px;
            color: var(--blue)
        }

        .todo-heading {
            display: flex;
            align-items: baseline;
            gap: 10px;
            margin-bottom: 9px
        }

        .todo-heading strong {
            font-size: 16px
        }

        .todo-heading span {
            color: var(--muted);
            font-size: 13px
        }

        .todo-meta {
            display: grid;
            gap: 5px
        }

        .todo-meta>div {
            display: grid;
            grid-template-columns: 62px minmax(0, 1fr);
            gap: 8px
        }

        .todo-meta b {
            font-size: 12px;
            text-transform: uppercase;
            color: var(--muted)
        }

        .todo-meta a,
        .todo-meta span {
            min-width: 0;
            overflow-wrap: anywhere
        }

        .todo-version label {
            margin: 0 0 6px
        }

        .todo-version input {
            width: 100%
        }

        @media(max-width:850px) {
            .todo-device {
                grid-template-columns: 58px minmax(0, 1fr)
            }

            .todo-version {
                grid-column: 2
            }
        }

        @media(max-width:520px) {
            .todo-device {
                grid-template-columns: 1fr;
                gap: 9px
            }

            .todo-number,
            .todo-version {
                grid-column: 1
            }

            .todo-number {
                padding-bottom: 0
            }

            .todo-meta>div {
                grid-template-columns: 54px minmax(0, 1fr)
            }
        }

        .version-choice {
            display: block;
            width: 100%;
            border: 0;
            background: transparent;
            text-align: left;
            cursor: pointer
        }

        .version-choice:hover {
            background: color-mix(in srgb, var(--blue) 12%, transparent)
        }

        .version-choice.selected {
            outline: 2px solid var(--blue);
            background: color-mix(in srgb, var(--blue) 16%, transparent)
        }

        #versionDetails {
            margin-top: 20px;
            padding-top: 18px;
            border-top: 1px solid var(--line)
        }

        .product-cve {
            padding: 7px 0
        }

        .sync-gate {
            position: fixed;
            inset: 0;
            z-index: 100;
            background: var(--bg);
            display: grid;
            place-items: center;
            padding: 24px
        }

        .sync-card {
            width: min(900px, 100%);
            background: var(--panel);
            border: 1px solid var(--line);
            padding: 24px
        }

        .sync-card pre {
            max-height: 42vh;
            overflow: auto;
            white-space: pre-wrap;
            border: 1px solid var(--line);
            padding: 12px;
            background: var(--bg)
        }

        .product-pager {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 14px;
            margin: 16px 0
        }

        .red-only-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(110px, 1fr));
            gap: 8px
        }

        .red-only-list .version-choice {
            border: 1px solid var(--line)
        }

        @media(prefers-color-scheme:dark) {
            :root {
                --bg: #171717;
                --panel: #222;
                --text: #e8e8e8;
                --muted: #aaa;
                --line: #444;
                --blue: #64a8e0;
                --red: #ff8a80;
                --yellow: #ffd166;
                --green: #77d18b
            }

            .primary {
                color: #111
            }
        }

        @media(max-width:760px) {
            header>div {
                display: block;
                padding: 14px
            }

            nav {
                margin-top: 10px
            }

            nav a {
                margin: 0 14px 0 0
            }

            main {
                padding: 12px
            }

            .cards,
            .report-grid {
                grid-template-columns: 1fr
            }

            .top {
                display: block
            }
        }
    </style>
</head>

<body>
    <header>
        <div>
            <div class="title"></div>
            <nav><a data-p="create">Prüfung</a><a data-p="view">Gespeicherte</a><a data-p="products">Produkte</a></nav>
        </div>
    </header>
    <main id="app"></main>
    <script>
        const C = <?= json_encode($pub, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP) ?>, Q = new URLSearchParams(location.search), A = document.getElementById('app'); let P = <?= json_encode($page) ?>;
        document.querySelector('.title').textContent = C.title;
        const pageUrls = { create: '?_page=create', view: '?_page=view', products: '?_page=products' };
        pageUrls[P] = location.search || ('?_page=' + P);
        function replaceParams(search) { for (const key of [...Q.keys()]) Q.delete(key); let q = new URLSearchParams(search); q.forEach((v, k) => Q.set(k, v)) }
        function rememberCurrentPage() { pageUrls[P] = location.search || ('?_page=' + P) }
        function updateNav() { document.querySelectorAll('[data-p]').forEach(x => { x.href = pageUrls[x.dataset.p] || ('?_page=' + x.dataset.p); x.classList.toggle('on', x.dataset.p === P) }) }
        function route(page, push = true) { let target = ['create', 'view', 'products'].includes(page) ? page : 'create'; if (push) rememberCurrentPage(); P = target; let search = push ? (pageUrls[P] || ('?_page=' + P)) : (location.search || ('?_page=' + P)); if (push) history.pushState({ page: P }, '', search); replaceParams(search); updateNav(); window.onbeforeunload = null; if (P === 'products') products(); else if (P === 'view') saved(); else createInputs() }
        document.querySelectorAll('[data-p]').forEach(x => x.addEventListener('click', ev => { ev.preventDefault(); route(x.dataset.p, true) }));
        window.addEventListener('popstate', () => { let q = new URLSearchParams(location.search), page = q.get('_page') || 'create'; P = ['create', 'view', 'products'].includes(page) ? page : 'create'; pageUrls[P] = location.search || ('?_page=' + P); route(P, false) });
        updateNav();
        const E = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
        async function request(a, q = {}, o = {}) { let r = await fetch('?' + new URLSearchParams({ _action: a, ...q }), { ...o, headers: { 'Content-Type': 'application/json' } }), j = await r.json(); if (!r.ok) throw Error(j.error || 'Fehler'); return j }
        const S = { versions: {}, results: {}, decisions: {}, entries: [], snapshots: [], dirty: false };
        function systemProduct(system){if(system.product&&C.products[system.product])return system.product;if(String(system.id||'').startsWith('1.'))return'fortios';if(system.id==='2.1'||system.id==='2.2')return'fortimanager';if(system.id==='2.3')return'fortianalyzer';throw new Error('Kein Produkt für System '+(system.id||'unbekannt')+' konfiguriert')}
        function createInputs() { A.innerHTML = `<section class="panel"><h1>Versionen erfassen</h1><p class="muted">Version oder N/A eintragen.</p><div class="input-list">${C.systems.map(s => `<article class="todo-device"><div class="todo-number">${E(s.id)}</div><div class="todo-content"><div class="todo-heading"><strong>${E(s.name)}</strong><span>${E(C.products[systemProduct(s)]?.label || systemProduct(s))}</span></div><div class="todo-meta"><div><b>Portal</b>${s.portal_url ? `<a href="${E(s.portal_url)}" target="_blank" rel="noopener noreferrer">${E(s.portal_url)}</a>` : '<span class="muted">unknown url</span>'}</div>${s.portal ? `<div><b>System</b><span>${E(s.portal)}</span></div>` : ''}${(s.access || []).map(x => `<div><b>${/^ADOM:/i.test(x) ? 'ADOM' : /^goto /i.test(x) ? 'Pfad' : 'Zugriff'}</b><span>${E(x.replace(/^ADOM:\s*/i, '').replace(/^goto\s*/i, ''))}</span></div>`).join('')}</div></div><div class="todo-version"><label for="version-${E(s.id)}">Version / N/A</label><input id="version-${E(s.id)}" data-system="${E(s.id)}" value="${E(Q.get('v_' + s.id) || '')}" placeholder="z. B. 7.6.7 oder N/A"></div></article>`).join('')}</div><div class="actions"><button class="primary" id="start">Weiter</button></div></section>`; document.querySelectorAll('[data-system]').forEach(x => x.oninput = () => { Q.set('v_' + x.dataset.system, x.value.trim()); history.replaceState(null, '', '?' + Q); pageUrls.create = '?' + Q; updateNav() }); document.getElementById('start').onclick = () => { let bad = []; C.systems.forEach(s => { let v = (Q.get('v_' + s.id) || '').trim(); if (!/^n\/?a$/i.test(v) && !/^\d+(\.\d+){1,3}$/.test(v)) bad.push(s.id); else S.versions[s.id] = /^n\/?a$/i.test(v) ? 'N/A' : v }); if (bad.length) return alert('Version oder N/A fehlt bei: ' + bad.join(', ')); scanPage() } }
        function scanPage() { A.innerHTML = `<section class="panel"><h1>Lokale Prüfung</h1><div id="scanList">${C.systems.filter(s => S.versions[s.id] !== 'N/A').map(s => `<article class="scan-row" id="scan-${E(s.id)}"><div class="top"><b>${E(s.id)} ${E(s.name)}</b><span class="scan-state">Wartet</span></div><div class="bar"><i></i></div><pre></pre><div class="scan-result"></div></article>`).join('')}</div><div class="actions"><button id="scanNext" class="primary" disabled>Weiter</button></div></section>`; runAllScans() }
        async function retryScan(s, v, row) { let pre = row.querySelector('pre'), bar = row.querySelector('.bar i'), state = row.querySelector('.scan-state'), attempt = 0, p = 4, t = setInterval(() => { p = Math.min(92, p + (94 - p) * .08); bar.style.width = p + '%' }, 500); while (true) { attempt++; state.textContent = 'Lokale Prüfung läuft'; pre.textContent += `${attempt === 1 ? 'Lokale Prüfung gestartet' : 'Fehler erkannt. Lokale Prüfung wird fortgesetzt'}\nProdukt: ${C.products[systemProduct(s)].label}\nQuelle: lokale CVE-Datenbank\n`; try { let x = await request('scan', { product: systemProduct(s), version: v }); clearInterval(t); bar.style.width = '100%'; pre.textContent += `Empfangen: ${x.received}\nRelevant: ${x.relevant}\nLokale CVE-Datensätze: ${x.received}\nQuelle: ${x.query_url}\nFertig\n`; state.textContent = 'Fertig'; return x } catch (e) { pre.textContent += `Hinweis: ${e.message}\nDie lokale Prüfung wird erneut versucht.\n`; if (attempt >= 5) { clearInterval(t); state.textContent = 'Erneut versuchen'; row.querySelector('.scan-result').innerHTML = `<button class="retry">Erneut versuchen</button>`; await new Promise(resolve => row.querySelector('.retry').onclick = resolve); row.querySelector('.scan-result').innerHTML = ''; attempt = 0 } } } }
        async function runAllScans() { for (const s of C.systems) { let v = S.versions[s.id]; if (v === 'N/A') continue; let row = document.getElementById('scan-' + s.id), x = await retryScan(s, v, row); S.results[s.id] = x; row.querySelector('.scan-result').innerHTML = `<span class="status ${x.status}">${E(v)} · ${x.status === 'red' ? 'betroffen' : x.status === 'yellow' ? 'prüfen' : 'kein Treffer'}</span>${(x.affected || []).map(c => `<div><a target="_blank" rel="noopener" href="${E(c.url)}">${E(c.id)}</a> · ${E(c.components.join(', '))}</div>`).join('')}`; S.snapshots.push({ system_id: s.id, product: systemProduct(s), checked_version: v, rows: x.rows, cves: x.affected, source_links: x.source_links }) } let b = document.getElementById('scanNext'); b.disabled = false; b.onclick = decisionsPage }
        function decisionsPage() { let reds = C.systems.filter(s => S.versions[s.id] !== 'N/A' && S.results[s.id]?.status === 'red'); if (!reds.length) return savePage(); A.innerHTML = `<section class="panel"><h1>Betroffenheit festlegen</h1>${reds.map(s => { let x = S.results[s.id]; return `<article class="decision-row"><h2>${E(s.id)} ${E(s.name)} · <span class="red">${E(S.versions[s.id])}</span></h2>${x.affected.map(c => `<div><a target="_blank" rel="noopener" href="${E(c.url)}">${E(c.id)}</a> · ${E(c.components.join(', '))}</div>`).join('')}<label>Betroffen?</label><select data-decision="${E(s.id)}"><option value="">Bitte wählen</option><option value="yes">Ja</option><option value="maybe">Vielleicht</option><option value="no">Nein</option></select><div id="parts-${E(s.id)}"></div></article>` }).join('')}<div class="actions"><button id="decisionNext" class="primary" disabled>Weiter</button></div></section>`; document.querySelectorAll('[data-decision]').forEach(x => x.onchange = () => { let s = C.systems.find(z => z.id === x.dataset.decision), parts = document.getElementById('parts-' + s.id), cs = [...new Set(S.results[s.id].affected.flatMap(c => c.components))]; S.decisions[s.id] = { answer: x.value, components: [] }; parts.innerHTML = ['yes', 'maybe'].includes(x.value) ? `${cs.map(c => `<label><input style="width:auto" type="checkbox" data-part="${E(s.id)}" value="${E(c)}"> ${E(c)}</label>`).join('')}<input data-own="${E(s.id)}" placeholder="Eigene Komponente">` : ''; validateDecisions() }); document.getElementById('decisionNext').onclick = () => { document.querySelectorAll('[data-part]:checked').forEach(x => S.decisions[x.dataset.part].components.push(x.value)); document.querySelectorAll('[data-own]').forEach(x => { if (x.value.trim()) S.decisions[x.dataset.own].components.push(x.value.trim()) }); savePage() } }
        function validateDecisions() { let ids = C.systems.filter(s => S.versions[s.id] !== 'N/A' && S.results[s.id]?.status === 'red').map(s => s.id); document.getElementById('decisionNext').disabled = !ids.every(id => S.decisions[id]?.answer) }
        function buildEntries() { return C.systems.map(s => { let v = S.versions[s.id]; if (v === 'N/A') return { system_id: s.id, name: s.name, product: C.products[systemProduct(s)].label, portal_url: s.portal_url || null, version: 'N/A', choice: 'na', text: '- N/A', status: 'na', cves: [] }; let x = S.results[s.id], d = S.decisions[s.id] || null, choice = x.status === 'green' ? 'latest' : 'plan'; return { system_id: s.id, name: s.name, product: C.products[systemProduct(s)].label, portal_url: s.portal_url || null, version: v, choice, text: choice === 'latest' ? `- ${v} is the latest stable release` : `- ${v} need to plan an Update`, status: x.status, decision: d, components: d?.components || [], cves: (x.affected || []).map(c => ({ id: c.id, url: c.url, components: c.components, published: c.published })) } }) }
        function isUserDecision(e) { return e.choice === 'na' || !!e.decision || e.user_decided === true }
        function savePage() { let date = new Date().toLocaleDateString('de-DE'), def = 'monthly check ' + date; A.innerHTML = `<section class="panel"><h1>Speichern</h1><label>Reportname</label><input id="rn" value="${E(def)}"><label>Attribut-Link-Name</label><input id="an" value="${E(def)}"><div class="actions"><button class="primary" id="save">Speichern</button></div></section>`; document.getElementById('save').onclick = async () => { let entries = buildEntries(), name = document.getElementById('rn').value.trim(), an = document.getElementById('an').value.trim(); if (!name || !an) return; let r = await request('save', {}, { method: 'POST', body: JSON.stringify({ mode: 'report', name, entries, snapshots: S.snapshots, source_links: [...new Set(S.snapshots.flatMap(x => x.source_links || []))] }) }); let a = await request('save', {}, { method: 'POST', body: JSON.stringify({ mode: 'attribute', report: r.report, name: an, values: entries.filter(isUserDecision) }) }); location.href = '?_page=view&report=' + r.report + '&_attr=' + a.attribute } }
        async function products() { A.innerHTML = `<section class="panel"><h1>Produkte</h1><div class="top"><div class="grow"><label>Produkt</label><select id="prod">${Object.entries(C.products).map(([k, v]) => `<option value="${k}">${E(v.label)}</option>`).join('')}</select></div></div><p class="muted">Die vollständige lokale Versions- und CVE-Datenbank wird verwendet. Eine Version direkt anklicken.</p><div class="actions"><button class="primary" id="go">Anzeigen</button></div><div id="pa"></div></section>`; let requested = Q.get('product'); if (requested && C.products[requested]) document.getElementById('prod').value = requested; document.getElementById('go').onclick = loadProductTable; document.getElementById('prod').onchange = () => { let q = new URLSearchParams(location.search); q.set('_page', 'products'); q.set('product', document.getElementById('prod').value); q.delete('version'); history.replaceState({ page: 'products' }, '', '?' + q); pageUrls.products = '?' + q; updateNav(); Q.set('product', document.getElementById('prod').value); Q.delete('version') }; if (requested && C.products[requested]) loadProductTable() }
        let productRows = [], productPage = 0, productSelected = null, productId = '';
        async function loadProductTable() { let e = document.getElementById('pa'); productId = document.getElementById('prod').value; e.innerHTML = '<div class="bar"><i style="width:70%"></i></div><pre>Lokale Daten werden ausgewertet …</pre>'; try { let x = await request('scan', { product: productId }); productRows = [...x.rows].sort((a, b) => b.version.localeCompare(a.version, undefined, { numeric: true })); productPage = 0; productSelected = Q.get('version') || null; if (productSelected) { let pos = productRows.findIndex(r => r.version === productSelected); if (pos >= 0) productPage = Math.floor(pos / 20) } renderProductPage(x); if (productSelected) { let b = document.querySelector(`[data-version-pick="${CSS.escape(productSelected)}"]`); if (b) inspectProductVersion(productId, productSelected, b) } } catch (err) { e.innerHTML = `<p class="red">${E(err.message)}</p><div class="actions"><button id="retryProduct">Erneut versuchen</button></div>`; document.getElementById('retryProduct').onclick = loadProductTable } }
        function renderProductPage(meta) { let e = document.getElementById('pa'), start = productPage * 20, rows = productRows.slice(start, start + 20), present = ['red', 'yellow', 'green'].filter(status => productRows.some(r => r.status === status)), pages = Math.max(1, Math.ceil(productRows.length / 20)), latest = meta?.latest ? `<p><b>Neueste stabile Version:</b> ${E(meta.latest)}</p>` : ''; if (present.length === 1 && present[0] === 'red') { e.innerHTML = `${latest}<div class="red-only-list">${rows.map(r => cell(r)).join('')}</div>${pager(pages)}<div id="versionDetails"><p class="muted">Version anklicken, um die betroffenen Bestandteile anzuzeigen.</p></div>` } else { e.innerHTML = `${latest}<table class="versions version-picker"><thead><tr>${present.map(s => `<th class="${s}">${s === 'red' ? 'Rot' : s === 'yellow' ? 'Gelb' : 'Grün'}</th>`).join('')}</tr></thead><tbody>${rows.map(r => `<tr>${present.map(s => `<td>${r.status === s ? cell(r) : ''}</td>`).join('')}</tr>`).join('')}</tbody></table>${pager(pages)}<div id="versionDetails"><p class="muted">Version anklicken, um die genaue Prüfung anzuzeigen.</p></div>` } bindProductPage(meta) }
        function pager(pages) { if (pages <= 1) return ''; return `<div class="product-pager"><button type="button" id="pagePrev" ${productPage === 0 ? 'disabled' : ''} aria-label="Vorherige Seite">←</button><span>Seite ${productPage + 1} / ${pages}</span><button type="button" id="pageNext" ${productPage + 1 >= pages ? 'disabled' : ''} aria-label="Nächste Seite">→</button></div>` }
        function bindProductPage(meta) { document.querySelectorAll('[data-version-pick]').forEach(b => b.onclick = () => inspectProductVersion(productId, b.dataset.versionPick, b)); document.getElementById('pagePrev')?.addEventListener('click', () => { productPage--; renderProductPage(meta) }); document.getElementById('pageNext')?.addEventListener('click', () => { productPage++; renderProductPage(meta) }); document.onkeydown = ev => { if (P !== 'products') return; if (ev.key === 'ArrowLeft' && productPage > 0) { productPage--; renderProductPage(meta) } if (ev.key === 'ArrowRight' && productPage + 1 < Math.ceil(productRows.length / 20)) { productPage++; renderProductPage(meta) } } }
        function cell(r) { return `<button type="button" class="version version-choice ${r.status} ${productSelected === r.version ? 'selected' : ''}" data-version-pick="${E(r.version)}">${E(r.version)}</button>` }
        async function inspectProductVersion(product, version, button) { productSelected = version; let q = new URLSearchParams(location.search); q.set('_page', 'products'); q.set('product', product); q.set('version', version); history.replaceState({ page: 'products' }, '', '?' + q); pageUrls.products = '?' + q; updateNav(); Q.set('product', product); Q.set('version', version); document.querySelectorAll('.version-choice.selected').forEach(x => x.classList.remove('selected')); button.classList.add('selected'); let e = document.getElementById('versionDetails'); e.innerHTML = `<div class="bar"><i style="width:65%"></i></div><pre>${E(version)} wird lokal geprüft …</pre>`; try { let x = await request('scan', { product, version }); e.innerHTML = `<h2>${E(version)} · <span class="${E(x.status)}">${x.status === 'red' ? 'Rot' : x.status === 'yellow' ? 'Gelb' : 'Grün'}</span></h2>${x.status === 'green' ? '<p>Für diese Version wurde kein passender CVE-Treffer gefunden.</p>' : x.affected.length ? `<h3>Betroffene Bestandteile</h3>${x.affected.map(c => `<div class="product-cve"><a href="${E(c.url)}" target="_blank" rel="noopener noreferrer">${E(c.id)}</a> · ${E(c.components.join(', '))}</div>`).join('')}` : '<p>Die Version liegt im Prüfbereich, es wurde aber kein direkt passender CVE-Treffer gefunden.</p>'}` } catch (err) { e.innerHTML = `<p class="red">${E(err.message)}</p><button id="retryVersion">Erneut versuchen</button>`; document.getElementById('retryVersion').onclick = () => inspectProductVersion(product, version, button) } }
        async function saved() { let rid = Q.get('report'), aid = Q.get('_attr'); if (rid) return report(rid, aid); let x = await request('list'); A.innerHTML = `<section class="panel"><h1>Gespeicherte Reports</h1><div class="list">${x.reports.map(r => `<button data-id="${E(r.id)}"><b>${E(r.name)}</b><br><span class="muted">${E(new Date(r.report_date).toLocaleString('de-DE'))}</span></button>`).join('') || '<p>Keine Reports.</p>'}</div></section>`; document.querySelectorAll('[data-id]').forEach(b => b.onclick = () => references(b.dataset.id)) }
        async function references(rid) { let [r, a] = await Promise.all([request('report', { id: rid }), request('attrs', { report: rid })]), x = r.report; A.innerHTML = `<section class="panel"><h1>${E(x.name)}</h1><p class="muted">Reportdatum: ${E(new Date(x.report_date).toLocaleString('de-DE'))}</p><div class="refbox"><b>Systemreferenzpunkt</b><br><a href="?_page=view&report=${E(rid)}">Ohne Entscheidungen öffnen</a></div>${a.attributes.map(z => `<div class="refbox"><b>${E(z.name)}</b><br><span class="muted">Attributdatum: ${E(new Date(z.date).toLocaleString('de-DE'))}</span><br><a href="?_page=view&report=${E(rid)}&_attr=${E(z.id)}">Öffnen</a></div>`).join('')}<div class="actions"><button onclick="location.href='?_page=view'">Zurück</button></div></section>` }
        async function report(rid, aid) {
            let r = (await request('report', { id: rid })).report, vals = structuredClone(r.system_attribute.values), dirty = false; if (aid) try { let av = (await request('attr', { id: aid })).attribute.values || []; let map = new Map(av.map(e => [e.system_id, e])); vals = vals.map(e => map.has(e.system_id) ? { ...e, ...map.get(e.system_id), user_decided: true } : e) } catch (e) { } A.innerHTML = `<div class="report-page"><div class="report-head"><div><h1>${E(r.name)}</h1><span class="muted">Reportdatum: ${E(new Date(r.report_date).toLocaleString('de-DE'))}</span></div><div class="report-buttons"><button id="backReport">Zurück</button><button id="copyReport">Kopieren</button><button class="primary" id="saveReport">Speichern</button></div></div><div id="reportBox" class="report-textbox" role="textbox" aria-multiline="true" aria-label="Reporttext">${renderReport(vals)}</div></div>`;
            const box = document.getElementById('reportBox');
            function plainChoice(e) { if (e.choice === 'na' || String(e.version).toUpperCase() === 'N/A') return '- N/A'; if (e.choice === 'latest') return `- ${e.version} is the latest stable release`; if (e.choice === 'uptodate') return `- ${e.version} up to date`; return `- ${e.version} need to plan an Update` }
            function plainText() { let one = vals.filter(e => String(e.system_id).startsWith('1.')), two = vals.filter(e => String(e.system_id).startsWith('2.')); let group = (title, intro, items) => title + '\n\n' + intro + '\n\n' + items.map(e => `(${e.system_id}) ${e.name}\n${plainChoice(e)}${selectedCves(e).length ? ' - ' + selectedCves(e).map(c => c.url).join(' ') : ''}`).join('\n\n'); return 'Monthly Check of Fortinet products\n\n\n' + group('(1) Fortinet Fortigate OS Check', 'Check Fortinet CVE reports. Updates required?', one) + '\n\n\n' + group('(2) Fortinet FortiManager and FortiAnalyzer version check', 'Check software versions and CVEs. Updates required?', two) }
            function bindDecisions() { box.querySelectorAll('[data-edit]').forEach(x => { x.onclick = () => openDecision(+x.dataset.edit) }) }
            function openDecision(i) { let e = vals[i], management = String(e.system_id).startsWith('2.'), current = e.choice || ((e.version === 'N/A') ? 'na' : management ? 'uptodate' : 'latest'); document.body.insertAdjacentHTML('beforeend', `<div class="overlay" id="decisionOverlay"><div class="dialog"><h2>${E(e.system_id)} ${E(e.name)}</h2><label>Version</label><input id="decisionVersion" value="${E(e.version)}"><label>Ausgabe</label><select id="decisionChoice"><option value="latest" ${current === 'latest' ? 'selected' : ''}>is the latest stable release</option>${management ? `<option value="uptodate" ${current === 'uptodate' ? 'selected' : ''}>up to date</option>` : ''}<option value="na" ${current === 'na' ? 'selected' : ''}>N/A</option><option value="plan" ${current === 'plan' ? 'selected' : ''}>need to plan an Update</option></select><div class="actions"><button id="cancelDecision">Abbrechen</button><button class="primary" id="applyDecision">Übernehmen</button></div></div></div>`); let ov = document.getElementById('decisionOverlay'); document.getElementById('decisionChoice').onchange = x => { document.getElementById('decisionVersion').disabled = x.target.value === 'na' }; document.getElementById('decisionVersion').disabled = current === 'na'; document.getElementById('cancelDecision').onclick = () => ov.remove(); document.getElementById('applyDecision').onclick = () => { let choice = document.getElementById('decisionChoice').value, version = document.getElementById('decisionVersion').value.trim(); if (choice !== 'na' && !/^\d+(\.\d+){1,3}$/.test(version)) return alert('Gültige Version eingeben.'); e.choice = choice; e.version = choice === 'na' ? 'N/A' : version; e.text = plainChoice(e); e.user_decided = true; dirty = true; box.innerHTML = renderReport(vals); bindDecisions(); ov.remove() } }
            bindDecisions();
            document.getElementById('copyReport').onclick = async () => { await navigator.clipboard.writeText(plainText()); let b = document.getElementById('copyReport'); b.textContent = 'Kopiert'; setTimeout(() => b.textContent = 'Kopieren', 1200) };
            async function leave() { if (dirty && !confirm('Ungespeicherte Änderungen verwerfen?')) return; window.onbeforeunload = null; location.href = '?_page=view&report=' + rid }
            document.getElementById('backReport').onclick = leave; window.onbeforeunload = () => dirty ? 'Ungespeicherte Änderungen' : undefined;
            document.getElementById('saveReport').onclick = () => { let d = new Date().toLocaleDateString('de-DE'), def = 'monthly check ' + d; document.body.insertAdjacentHTML('beforeend', `<div class="overlay" id="saveOverlay"><div class="dialog"><h2>Neuen Attribut-Link speichern</h2><label>Name</label><input id="attrName" value="${E(def)}"><div class="actions"><button id="cancelSave">Abbrechen</button><button class="primary" id="doSave">Speichern</button></div></div></div>`); let ov = document.getElementById('saveOverlay'); document.getElementById('cancelSave').onclick = () => ov.remove(); document.getElementById('doSave').onclick = async () => { let name = document.getElementById('attrName').value.trim(); if (!name) return; let x = await request('save', {}, { method: 'POST', body: JSON.stringify({ mode: 'attribute', report: rid, name, values: vals.filter(isUserDecision) }) }); dirty = false; window.onbeforeunload = null; location.href = '?_page=view&report=' + rid + '&_attr=' + x.attribute } }
        }
        function renderReport(vals) { let one = [], two = []; vals.forEach((e, i) => (String(e.system_id).startsWith('2.') ? two : one).push([e, i])); let group = (heading, intro, items) => `<div class="report-section-title">${E(heading)}</div><div class="report-intro">${E(intro)}</div>${items.map(([e, i]) => renderReportEntry(e, i)).join('')}`; return `<div class="report-main-title">Monthly Check of Fortinet products</div>${group('(1) Fortinet Fortigate OS Check', 'Check Fortinet CVE reports. Updates required?', one)}${group('(2) Fortinet FortiManager and FortiAnalyzer version check', 'Check software versions and CVEs. Updates required?', two)}` }
        function selectedCves(e) { let all = e.cves || [], ids = e.selected_cves || e.selectedCves || e.decision?.selected_cves || e.decision?.selectedCves || []; if (ids.length) return all.filter(c => ids.includes(c.id)); let selected = e.decision?.components || e.components || []; if (selected.length === 1) { let matching = all.filter(c => (c.components || []).includes(selected[0])); if (matching.length) return matching } return all }
        function renderReportEntry(e, i) { let choice = e.choice || ((e.version === 'N/A') ? 'na' : String(e.system_id).startsWith('2.') ? 'uptodate' : 'latest'), text = choice === 'na' ? '- N/A' : choice === 'latest' ? `- ${e.version} is the latest stable release` : choice === 'uptodate' ? `- ${e.version} up to date` : `- ${e.version} need to plan an Update`, links = selectedCves(e).map(c => ` - <a href="${E(c.url)}" target="_blank" rel="noopener noreferrer">${E(c.url)}</a>`).join(''), editable = isUserDecision(e); return `<div class="report-entry-text"><div>(${E(e.system_id)}) ${E(e.name)}</div><div>${editable ? `<button type="button" class="editable-report-part" data-edit="${i}" title="Diese Entscheidung ändern">${E(text)}</button>` : `<span class="automatic-report-part">${E(text)}</span>`}${links}</div></div>` }
        async function bootstrap() {
            const createDeepLink = P === 'create' && [...Q.keys()].some(key => key.startsWith('v_'));
            if (createDeepLink) return true;
            let status = await request('sync_status');
            let missing = [...status.missing];
            for (const pid of Object.keys(C.products)) {
                if (missing.includes(pid)) continue;
                let failures = 0;
                while (true) {
                    try { let probe = await request('sync_probe', { product: pid }); if (probe.stale) missing.push(pid); break; }
                    catch (err) { failures++; if (failures >= 3) break; await new Promise(r => setTimeout(r, failures * 1500)); }
                }
            }
            if (!missing.length) return true;
            status.missing = [...new Set(missing)];
            document.body.insertAdjacentHTML('beforeend', `<div class="sync-gate" id="syncGate"><div class="sync-card"><h1>Lokale Fortinet-Daten werden vorbereitet</h1><div class="bar"><i id="syncBar"></i></div><div id="syncCurrent"></div><pre id="syncLog"></pre></div></div>`);
            let log = document.getElementById('syncLog'), bar = document.getElementById('syncBar'), current = document.getElementById('syncCurrent');
            for (let i = 0; i < status.missing.length; i++) {
                let pid = status.missing[i], failures = 0;
                while (true) {
                    try {
                        let step = await request('sync_step', { product: pid }); failures = 0;
                        let label = C.products[pid]?.label || pid, overall = ((i + (step.progress || 0) / 100) / status.missing.length) * 100;
                        bar.style.width = overall + '%'; current.textContent = `${label}: ${step.message || 'Abgeschlossen'}`;
                        log.textContent += `[${label}] ${step.message || 'Abgeschlossen'}${step.url ? '\n' + step.url : ''}\n`; log.scrollTop = log.scrollHeight;
                        if (step.done) break;
                    } catch (err) {
                        failures++; log.textContent += `Timeout/Fehler: ${err.message}\nFortsetzung ${failures} wird gestartet …\n`; await new Promise(r => setTimeout(r, Math.min(15000, failures * 2000)));
                    }
                }
            }
            bar.style.width = '100%'; current.textContent = 'Alle lokalen Produktdaten sind vollständig.'; await new Promise(r => setTimeout(r, 500)); document.getElementById('syncGate').remove(); return true;
        }
        bootstrap().then(() => route(P, false)).catch(err => { A.innerHTML = `<section class="panel"><h1>Synchronisation nicht möglich</h1><p class="red">${E(err.message)}</p><button onclick="location.reload()">Neu laden</button></section>` });

    </script>
</body>

</html>
