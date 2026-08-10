<?php

declare(strict_types=1);

require '/var/www/roundcube-1.7.3/program/include/iniset.php';
require dirname(__DIR__) . '/lib/mcpcube_crypto.php';
require dirname(__DIR__) . '/lib/mcpcube_auth_context.php';
require dirname(__DIR__) . '/lib/mcpcube_mcp_protocol.php';

$context = (new ReflectionClass(mcpcube_auth_context::class))->newInstanceWithoutConstructor();
$server = new mcpcube_mcp_server();

foreach (mcpcube_mcp_server::SUPPORTED_PROTOCOL_VERSIONS as $version) {
    $response = $server->handle([
        'jsonrpc' => '2.0',
        'id' => 1,
        'method' => 'initialize',
        'params' => ['protocolVersion' => $version, 'capabilities' => [], 'clientInfo' => ['name' => 'smoke', 'version' => '1']],
    ], $context);

    if (($response['result']['protocolVersion'] ?? null) !== $version) {
        throw new RuntimeException("Protocol negotiation failed for {$version}");
    }
}

$invalid = $server->handle(['jsonrpc' => '1.0', 'id' => 2, 'method' => 'ping'], $context);
if (($invalid['error']['code'] ?? null) !== -32600) {
    throw new RuntimeException('Invalid JSON-RPC version was not rejected');
}

$structured = mcpcube_mcp_server::json_result(['ok' => true]);
if (($structured['structuredContent']['ok'] ?? null) !== true) {
    throw new RuntimeException('Structured tool content is missing');
}

echo "protocol smoke tests passed\n";
