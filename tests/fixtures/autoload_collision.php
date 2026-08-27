<?php

declare(strict_types=1);

$projectRoot = dirname(__DIR__, 2);
$hostRoot = sys_get_temp_dir() . '/oidc-cube-host-' . bin2hex(random_bytes(8));

function copyTree(string $source, string $destination): void
{
    if (!mkdir($destination, 0700, true) && !is_dir($destination)) {
        throw new RuntimeException("Unable to create {$destination}");
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($source, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );

    foreach ($iterator as $item) {
        $target = $destination . DIRECTORY_SEPARATOR . $iterator->getSubPathName();
        if ($item->isDir()) {
            if (!mkdir($target, 0700) && !is_dir($target)) {
                throw new RuntimeException("Unable to create {$target}");
            }
        } elseif (!copy($item->getPathname(), $target)) {
            throw new RuntimeException("Unable to copy {$target}");
        }
    }
}

function removeTree(string $directory): void
{
    if (!is_dir($directory)) {
        return;
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );

    foreach ($iterator as $item) {
        $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
    }

    rmdir($directory);
}

register_shutdown_function(static fn() => removeTree($hostRoot));

copyTree(
    $projectRoot . '/vendor/pear/pear-core-minimal/src',
    $hostRoot . '/vendor/pear/pear-core-minimal/src'
);
copyTree(
    $projectRoot . '/vendor/pear/mail_mime',
    $hostRoot . '/vendor/pear/mail_mime'
);

define('RCUBE_INSTALL_PATH', $hostRoot . '/');
set_include_path(implode(PATH_SEPARATOR, [
    RCUBE_INSTALL_PATH . 'vendor/pear/pear-core-minimal/src',
    RCUBE_INSTALL_PATH . 'vendor/pear/mail_mime',
    get_include_path(),
]));

require RCUBE_INSTALL_PATH . 'vendor/pear/pear-core-minimal/src/PEAR.php';

class rcube_plugin
{
    public function init(): void
    {
    }
}

require $projectRoot . '/roundcube_oidc.php';

$mail = new Mail_mime();
$reflection = new ReflectionClass($mail);

if (!str_starts_with((string) $reflection->getFileName(), RCUBE_INSTALL_PATH)) {
    throw new RuntimeException('Mail_mime was loaded from the plugin dependency tree');
}

echo "OK\n";
