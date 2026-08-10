<?php

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';
require dirname(__DIR__) . '/lib/mcpcube_sandbox.php';

final class mcpcube_smoke_api
{
    public function add(int $left, int $right): int
    {
        return $left + $right;
    }
}

$result = mcpcube_sandbox::run(
    '$values = []; for ($i = 0; $i < 3; $i++) { $values[] = $api->add($i, 2); } return $values;',
    ['api' => new mcpcube_smoke_api()]
);

if ($result['return'] !== [2, 3, 4]) {
    throw new RuntimeException('Sandbox arithmetic/control-flow smoke test failed');
}

foreach (['return file_get_contents("/etc/passwd");', 'return new stdClass();', 'return $api->{"add"}(1, 2);'] as $unsafe) {
    try {
        mcpcube_sandbox::run($unsafe, ['api' => new mcpcube_smoke_api()]);
        throw new RuntimeException('Sandbox accepted an unsafe construct');
    } catch (mcpcube_sandbox_error) {
        // Expected: rejected by the AST allow-list before execution.
    }
}

echo "sandbox smoke tests passed\n";
