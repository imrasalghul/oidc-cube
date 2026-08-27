<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class AutoloadIsolationTest extends TestCase
{
    public function testPluginDoesNotShadowHostRoundcubePearDependencies(): void
    {
        $fixture = __DIR__ . '/fixtures/autoload_collision.php';
        $process = proc_open(
            [PHP_BINARY, '-d', 'display_errors=1', $fixture],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes
        );

        self::assertIsResource($process);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $status = proc_close($process);

        self::assertSame(0, $status, $stdout . $stderr);
        self::assertSame("OK\n", $stdout);
        self::assertSame('', $stderr);
    }
}
