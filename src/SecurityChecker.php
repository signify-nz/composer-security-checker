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

    private $advisoriesDir;
    private $advisories;
    private $hasAdvisories = false;

    /**
     * @param string|null $advisoriesDir Directory where advisories URL should be written.
     * @throws InvalidArgumentException
     */
    public function __construct(string $advisoriesDir = null)
    {
        if ($advisoriesDir) {
            if (!is_dir($advisoriesDir) || !is_writable($advisoriesDir)) {
                throw new InvalidArgumentException("Directory '$advisoriesDir' must exist and be writable.");
            }
        } else {
            $this->advisoriesDir = sys_get_temp_dir() . '/signify-nz/advisories';
        }
    }

    /**
     * Checks a composer.lock file for vulnerable dependencies.
     *
     * @param string $lock The path to the composer.lock file
     * @return string[]
     * @throws InvalidArgumentException When the lock file does not exist or contains data in the wrong format.
     */
    public function check(string $lock)
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
    public function checkFromJson(array $lock)
    {
        $this->fetchAdvisories();
        $this->instantiateAdvisories();
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
                            if ($packageTimestamp === $zeroUTC || $packageTimestamp > strtotime($branch['time'] . ' UTC')) {
                                continue;
                            }
                        } else {
                            // For stable packages, skip if advisory constraints don't satisfy installed version.
                            if (!Semver::satisfies($package['version'], $branch['versions'])) {
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
        return $advisories;
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

    protected function fetchAdvisories()
    {
        if ($this->hasAdvisories) {
            return;
        }

        if (is_dir($this->advisoriesDir)) {
            //TODO: Compare master commit hash and don't re-fetch if it's already there.
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
        $zip->extractTo($this->advisoriesDir);
        $zip->close();

        //TODO: Validate using validator.php

        $this->hasAdvisories = true;
    }

    protected function instantiateAdvisories()
    {
        if (!empty($this->advisories)) {
            return;
        }

        // Scan for organisation directories.
        $dir = $this->advisoriesDir . '/security-advisories-master';
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

        $this->advisories = [];
    }

    protected function getPackages(array $lock)
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
