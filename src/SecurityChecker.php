<?php

namespace Signify\SecurityChecker;

use Composer\Semver\Semver;
use FilesystemIterator;
use GuzzleHttp\Client as GuzzleClient;
use InvalidArgumentException;
use LogicException;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RecursiveRegexIterator;
use RegexIterator;
use Symfony\Component\Yaml\Yaml;
use ZipArchive;

class SecurityChecker
{
    public const ADVISORIES_URL = 'https://codeload.github.com/FriendsOfPHP/security-advisories/zip/master';
    // Don't allow execution, since we're grabbing files from a source we don't control.
    public const FILE_PERMISSIONS = 0666;

    private $advisories;
    private $options;

    /**
     * @param array $options The options for this checker.
     * @throws InvalidArgumentException if the advisories directory isn't writable.
     * @throws LogicException if the request for the advisories package returns a response code >= 300
     */
    public function __construct(array $options = [])
    {
        // Set options.
        $this->options = array_merge(
            [
                'advisories-dir' => sys_get_temp_dir() . '/signify-nz-security/advisories',
                'advisories-stale-after' => 86400, // 24 hrs in seconds.
                'guzzle-options' => [],
            ],
            $options
        );

        $this->validateOptions();

        // Get the advisories.
        $this->fetchAdvisories();
        $this->instantiateAdvisories();
    }

    /**
     * Checks a composer.lock file for vulnerable dependencies.
     *
     * @param string|array $lock The absolute path to the composer.lock file, or the json_decoded array.
     * @param boolean $includeDev If false, the dev dependencies won't be checked.
     * @return array
     * @throws InvalidArgumentException When the lock file does not exist or contains data in the wrong format.
     */
    public function check($lock, bool $includeDev = true): array
    {
        if (is_string($lock)) {
            if (!is_file($lock)) {
                throw new InvalidArgumentException('Lock file does not exist.');
            }
            $lockContents = json_decode(file_get_contents($lock), true);
            if (!is_array($lockContents)) {
                throw new InvalidArgumentException('Lock file does not contain correct format.');
            }
        } elseif (is_array($lock)) {
            $lockContents = $lock;
        } else {
            throw new InvalidArgumentException(
                '$lock must be the absolute path to the composer.lock file, '
                . 'or the json_decoded associative array of the composer.lock contents.'
            );
        }
        return $this->checkFromJson($lockContents, $includeDev);
    }

    /**
     * Checks JSON in the format of a composer.lock file for vulnerable dependencies.
     *
     * @param array $lock The json_decoded array in the format of a composer.lock file
     * @param boolean $includeDev If false, the dev dependencies won't be checked.
     * @return array
     * @throws InvalidArgumentException When the lock file does not exist
     */
    protected function checkFromJson(array $lock, bool $includeDev): array
    {
        $vulnerabilities = [];
        $zeroUTC = strtotime('1970-01-01T00:00:00+00:00');
        // Check all packages for vulnerabilities.
        foreach ($this->getPackages($lock, $includeDev) as $package) {
            $advisories = [];
            // Check for advisories about this specific package.
            if (array_key_exists($package['name'], $this->advisories)) {
                $normalisedVersion = $this->normalizeVersion($package['version']);
                foreach ($this->advisories[$package['name']] as $advisory) {
                    // Check each branch of the advisory to see if the installed version is affected.
                    foreach ($advisory['branches'] as $branchName => $branch) {
                        if ($this->isDev($package['version'])) {
                            // For dev packages, skip if not using the advisory branch.
                            $branchName = StringUtil::removeFromEnd($branchName, '.x');
                            if ($branchName !== $normalisedVersion) {
                                continue;
                            }
                            // For dev packages, skip if the advisory branch is older than the installed version.
                            $packageTimestamp = strtotime($package['time'] . ' UTC');
                            if ($packageTimestamp === $zeroUTC || $packageTimestamp > $branch['time']) {
                                continue;
                            }
                        } else {
                            // For stable packages, skip if installed version doesn't satisfy the advisory constraints.
                            if (!Semver::satisfies($package['version'], implode(',', $branch['versions']))) {
                                continue;
                            }
                        }
                        // If we got this far, the advisory applies for the installed package.
                        // Unset the unnecessary information.
                        unset($advisory['branches']);
                        unset($advisory['reference']);
                        $advisories[] = $advisory;
                        // Break the branch loop - we've already confirmed this advisory.
                        break;
                    }
                }
            }
            // Add relevant advisories to the resultant vulnerabilities array.
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

    /**
     * Get an option for this checker.
     *
     * @param string $option The option to get.
     * @return mixed The option value, or null if it doesn't exist.
     */
    public function getOption(string $option)
    {
        if (isset($this->options[$option])) {
            return $this->options[$option];
        }
        return null;
    }

    /**
     * Get an array of packages which are included in the composer lock.
     *
     * @param array $lock Composer lock JSON as an associative array.
     * @return array
     */
    public function getPackages(array $lock, bool $includeDev = true): array
    {
        $packages = [];
        $packageKeys = ['packages'];
        if ($includeDev) {
            $packageKeys[] = 'packages-dev';
        }
        foreach ($packageKeys as $key) {
            if (!array_key_exists($key, $lock)) {
                continue;
            }
            $packages = array_merge($packages, $lock[$key]);
        }
        return $packages;
    }

    protected function validateOptions()
    {
        // Confirm advisories directory can be written to (and create it if needs be)
        $advisoriesDir = $this->getOption('advisories-dir');
        $old_umask = umask(0);
        if ((!is_dir($advisoriesDir) && !mkdir($advisoriesDir, 0777, true)) || !is_writable($advisoriesDir)) {
            umask($old_umask);
            throw new InvalidArgumentException("Directory '$advisoriesDir' must be writable.");
        }
        umask($old_umask);
    }

    /**
     * Normalise a dev package version to easily compare with advisory branches.
     *
     * @param string $version
     * @return string
     */
    protected function normalizeVersion(string $version): string
    {
        $version = StringUtil::removeFromStart($version, 'dev-');
        $version = StringUtil::removeFromEnd($version, ['.x-dev', '-dev']);
        return $version;
    }

    /**
     * Check if the package version is for a dev package.
     *
     * @param string $version
     * @return boolean
     */
    protected function isDev(string $version): bool
    {
        $version = preg_replace('/"#.+$/', '', $version);
        if (StringUtil::startsWith($version, 'dev-') || StringUtil::endsWith($version, '-dev')) {
            return true;
        }

        return false;
    }

    /**
     * Fetch advisories from FriendsOfPHP.
     *
     * @return void
     */
    protected function fetchAdvisories(): void
    {
        $advisoriesDir = $this->getOption('advisories-dir');
        $timestampFile = $advisoriesDir . '/timestamp.txt';
        // Don't fetch if we still have advisories and they aren't stale.
        if (is_file($timestampFile) && !$this->isStale(file_get_contents($timestampFile))) {
            return;
        }

        // Fetch advisories zip from github.
        $client = new GuzzleClient();
        $response = $client->request('GET', self::ADVISORIES_URL, $this->getOption('guzzle-options'));
        if ($response->getStatusCode() >= 300) {
            throw new LogicException('Got status code ' . $response->getStatusCode() . ' when requesting advisories.');
        }

        // Store zip temporarily so it can be unzipped.
        $file = tempnam(sys_get_temp_dir(), 'zip');
        file_put_contents($file, $response->getBody());

        // Unzip advisories repository.
        $zip = new ZipArchive();
        $zip->open($file);
        $zip->extractTo($advisoriesDir);
        $zip->close();

        // Remove temporary zip file
        unlink($file);

        // Add timestamp to the directory so we don't refetch unnecessarily.
        file_put_contents($timestampFile, time());

        // Ensure all files have correct permissions.
        $this->setFilePermissionsRecursive($advisoriesDir);
    }

    /**
     * Recursively set permissions for all files nested inside some directory.
     *
     * @param string $dir
     * @return void
     * @throws InvalidArgumentException if $dir is not a directory.
     */
    private function setFilePermissionsRecursive(string $dir): void
    {
        if (!is_dir($dir)) {
            throw new InvalidArgumentException("$dir must be a directory.");
        }
        $recursion = new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS);
        foreach (new RecursiveIteratorIterator($recursion) as $item) {
            chmod($item->getPathname(), self::FILE_PERMISSIONS);
        }
    }

    /**
     * Check if a timestamp is outside the permitted timeframe.
     *
     * @param string|int $timestamp The unix timestamp to check for staleness.
     * @return boolean
     */
    protected function isStale($timestamp): bool
    {
        return ((int)$timestamp) < (time() - $this->getOption('advisories-stale-after'));
    }

    /**
     * Read advisory yaml files from the FriendsOfPHP repo into memory.
     *
     * @return void
     */
    protected function instantiateAdvisories(): void
    {
        if (!empty($this->advisories)) {
            return;
        }
        $this->advisories = [];

        // Parse all yaml files.
        $dir = $this->getOption('advisories-dir') . '/security-advisories-master/';
        $recursiveIterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
        );
        // Match all files with a .yml or .yaml extension within our directory which are not in hidden directories.
        $regex = '/^' . preg_quote($dir, '/') . '[^.]+\.(yaml|yml)$/i';
        foreach (new RegexIterator($recursiveIterator, $regex, RecursiveRegexIterator::GET_MATCH) as $match) {
            $filename = $match[0];
            // Parse yaml and store advisory against package name.
            $advisory = Yaml::parseFile($filename);
            $packageName = preg_replace('/^composer:\/\//', '', $advisory['reference']);
            $this->advisories[$packageName][] = $advisory;
        }
    }
}
