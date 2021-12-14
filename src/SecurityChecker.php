<?php

namespace Signify\SecurityChecker;

use Composer\Semver\Semver;
use GuzzleHttp\Client;
use InvalidArgumentException;
use LogicException;
use Symfony\Component\Yaml\Yaml;
use ZipArchive;

class SecurityChecker
{
    public const ADVISORIES_URL = 'https://codeload.github.com/FriendsOfPHP/security-advisories/zip/master';

    private $advisories;
    private $options;

    /**
     * @param array $options The options for this checker.
     * @throws InvalidArgumentException
     */
    public function __construct(array $options = [])
    {
        $this->options = array_merge(
            [
                'advisories-dir' => sys_get_temp_dir() . '/signify-nz-security/advisories',
                'advisories-stale-after' => 86400, // 24 hrs in seconds.
            ],
            $options
        );

        $advisoriesDir = $this->options['advisories-dir'];
        if (!is_dir($advisoriesDir) && !mkdir($advisoriesDir, 0777, true)) {
            throw new InvalidArgumentException("Directory '$advisoriesDir' must be writable.");
        }

        $this->fetchAdvisories();
        $this->instantiateAdvisories();
    }

    /**
     * Checks a composer.lock file for vulnerable dependencies.
     *
     * @param string $lock The path to the composer.lock file
     * @return string[]
     * @throws InvalidArgumentException When the lock file does not exist or contains data in the wrong format.
     */
    public function check(string $lock): array
    {
        if (!is_file($lock)) {
            throw new InvalidArgumentException('Lock file does not exist.');
        }
        $lockContents = json_decode(file_get_contents($lock), true);
        if (!is_array($lockContents)) {
            throw new InvalidArgumentException('Lock file does not contain correct format.');
        }
        return $this->checkFromJson($lockContents);
    }

    /**
     * Checks JSON in the format of a composer.lock file for vulnerable dependencies.
     *
     * @param array $lock The json_decoded array in the format of a composer.lock file
     * @return string[]
     * @throws InvalidArgumentException When the lock file does not exist
     */
    public function checkFromJson(array $lock): array
    {
        $vulnerabilities = [];
        $zeroUTC = strtotime('1970-01-01T00:00:00+00:00');
        foreach ($this->getPackages($lock) as $package) {
            $advisories = [];
            if (array_key_exists($package['name'], $this->advisories)) {
                $normalisedVersion = $this->normalizeVersion($package['version']);
                foreach ($this->advisories[$package['name']] as $advisory) {
                    foreach ($advisory['branches'] as $branchName => $branch) {
                        if ($this->isDev($package['version'])) {
                            // For dev packages, skip if not using the advisory branch.
                            $branchName = StringUtil::removeFromEnd($branchName, '.x');
                            if ($branchName !== $normalisedVersion) {
                                continue;
                            }
                            // For dev packages, skip if not using the advisory branch is older than installed version.
                            $packageTimestamp = strtotime($package['time'] . ' UTC');
                            if ($packageTimestamp === $zeroUTC || $packageTimestamp > $branch['time']) {
                                continue;
                            }
                        } else {
                            // For stable packages, skip if advisory constraints don't satisfy installed version.
                            if (!Semver::satisfies($package['version'], implode(',', $branch['versions']))) {
                                continue;
                            }
                        }
                        // If we got this far, the advisory applies for the installed package.
                        $advisories[] = $advisory;
                        // Break the branch loop - we've already confirmed this advisory.
                        break;
                    }
                }
            }
            if (!empty($advisories)) {
                $vulnerabilities[$package['name']] = [
                    'version' => $package['version'],
                    'advisories' => $advisories,
                ];
            }
        }
        return $vulnerabilities;
    }

    /**
     * Get the array of options for this checker.
     *
     * @return string[]
     */
    public function getOptions(): array
    {
        return $this->options;
    }

    protected function normalizeVersion(string $version): string
    {
        $version = StringUtil::removeFromStart($version, 'dev-');
        $version = StringUtil::removeFromEnd($version, ['.x-dev', '-dev']);
        return $version;
    }

    protected function isDev(string $rawVersion): bool
    {
        $version = preg_replace('/"#.+$/', '', $rawVersion);
        if (StringUtil::startsWith($version, 'dev-') || StringUtil::endsWith($version, '-dev')) {
            return true;
        }

        return false;
    }

    protected function fetchAdvisories(): void
    {
        $advisoriesDir = $this->options['advisories-dir'];
        $timestampFile = $advisoriesDir . '/timestamp.txt';
        // Don't fetch if we still have advisories and they aren't stale.
        if (is_file($timestampFile) && !$this->isStale(file_get_contents($timestampFile))) {
            return;
        }

        // Fetch advisories zip from github.
        $client = new Client();
        $response = $client->request('GET', self::ADVISORIES_URL);
        if ($response->getStatusCode() >= 300) {
            throw new LogicException('Got status code ' . $response->getStatusCode() . ' when requesting advisories.');
        }

        // Store zip temporarily so it can be unzipped.
        $file = tempnam(sys_get_temp_dir(), 'zip');
        file_put_contents($file, $response->getBody());

        // Unzip advisories repository.
        $zip = new ZipArchive;
        $zip->open($file);
        $zip->extractTo($advisoriesDir);
        $zip->close();

        // Add timestamp to the directory so we don't refetch unnecessarily.
        file_put_contents($timestampFile, time());
    }

    /**
     * Check if a timestamp is outside the permitted timeframe.
     *
     * @param string|int $timestamp The unix timestamp to check for staleness.
     * @return boolean
     */
    protected function isStale($timestamp): bool
    {
        return ((int)$timestamp) < (time() - $this->options['advisories-stale-after']);
    }

    protected function instantiateAdvisories(): void
    {
        if (!empty($this->advisories)) {
            return;
        }

        $this->advisories = [];

        // Scan for organisation directories.
        $dir = $this->options['advisories-dir'] . '/security-advisories-master';
        foreach ((array)scandir($dir) as $org) {
            $orgDir = $dir . '/' . $org;
            // Ignore hidden directories and dot directories, and any files.
            if (strpos($org, '.') === 0 || !is_dir($orgDir)) {
                continue;
            }

            // Scan organisations for package directories.
            foreach ((array)scandir($orgDir) as $package) {
                $packageDir = $orgDir . '/' . $package;
                // Ignore hidden directories and dot directories, and any files.
                if (strpos($package, '.') === 0 || !is_dir($packageDir)) {
                    continue;
                }

                // Scan packages for advisories.
                foreach ((array)scandir($packageDir) as $fileName) {
                    $filePath = $packageDir . '/' . $fileName;
                    // Ignore directories and any non-yaml file.
                    if (!is_file($filePath) || !StringUtil::endsWith($fileName, ['.yml', '.yaml'])) {
                        continue;
                    }

                    $advisory = Yaml::parseFile($filePath);
                    $packageName = preg_replace('/^composer:\/\//', '', $advisory['reference']);
                    $this->advisories[$packageName][] = $advisory;
                }
            }
        }
    }

    protected function getPackages(array $lock): array
    {
        $packages = [];
        foreach (['packages', 'packages-dev'] as $key) {
            if (!array_key_exists($key, $lock)) {
                continue;
            }
            $packages = array_merge($packages, $lock[$key]);
        }
        return $packages;
    }
}
