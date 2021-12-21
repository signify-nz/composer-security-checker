<?php

namespace Signify\SecurityChecker\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Signify\SecurityChecker\SecurityChecker;

final class SecurityCheckerTest extends TestCase
{
    private $securityChecker;

    public function testStaleAfterConfig()
    {
        $checker = $this->getDefaultSecurityChecker();
        // Get the timestamp from the first instantiation.
        $filePath = $checker->getOption('advisories-dir') . '/timestamp.txt';
        $timestamp1 = (int)file_get_contents($filePath);

        // Wait for a second to be certain the next instantiation isn't done on the same second.
        sleep(1);
        // Use default (24 hours) stale time.
        new SecurityChecker();
        $timestamp2 = (int)file_get_contents($filePath);
        $this->assertEquals($timestamp1, $timestamp2);

        // Wait for a second to be certain the next instantiation isn't done on the same second.
        sleep(1);
        // Use a custom stale timeout that will not have expired.
        new SecurityChecker(['advisories-stale-after' => 3600]);
        $timestamp3 = (int)file_get_contents($filePath);
        $this->assertEquals($timestamp1, $timestamp3);

        // Wait for a second to be certain the next instantiation isn't done on the same second.
        sleep(1);
        // Force the contents to be stale.
        new SecurityChecker(['advisories-stale-after' => 0]);
        $timestamp4 = (int)file_get_contents($filePath);
        $this->assertGreaterThan($timestamp1, $timestamp4);
    }

    public function testUnwritableDirectory()
    {
        $this->expectException(InvalidArgumentException::class);
        $unwritableDir = sys_get_temp_dir() . '/security-checker-unwritable';
        mkdir($unwritableDir, 0);
        try {
            new SecurityChecker(['advisories-dir' => $unwritableDir]);
        } catch (InvalidArgumentException $e) {
            rmdir($unwritableDir);
            throw $e;
        }
    }

    public function testWritableDirectory()
    {
        $dir = $this->getWritableDir();
        $beforeSetupTimestamp = time();
        new SecurityChecker([
            'advisories-dir' => $dir,
            'advisories-stale-after' => 0
        ]);
        // Confirm that there is a timestamp file, and it was created as a part of this test.
        $filePath = $dir . '/timestamp.txt';
        $this->assertTrue(is_file($filePath));
        $newTimestamp = (int)file_get_contents($filePath);
        $this->assertGreaterThanOrEqual($beforeSetupTimestamp, $newTimestamp);
    }

    public function testGetOptions()
    {
        $defaults = [
            'advisories-dir' => sys_get_temp_dir() . '/signify-nz-security/advisories',
            'advisories-stale-after' => 86400,
            'guzzle-options' => [],
        ];
        $defaultChecker = $this->getDefaultSecurityChecker();
        $this->assertSame($defaults, $defaultChecker->getOptions());
        foreach ($defaults as $key => $value) {
            $this->assertSame($value, $defaultChecker->getOption($key));
        }

        $testOptions = [
            'advisories-dir' => $this->getWritableDir(),
            'advisories-stale-after' => 3600,
            'guzzle-options' => ['timeout' => 0],
        ];
        $testChecker = new SecurityChecker($testOptions);
        $this->assertSame($testOptions, $testChecker->getOptions());
        foreach ($testOptions as $key => $value) {
            $this->assertSame($value, $testChecker->getOption($key));
        }
    }

    public function testCheckNoFileFail()
    {
        $this->expectException(InvalidArgumentException::class);
        $checker = $this->getDefaultSecurityChecker();
        $checker->check(dirname(__FILE__) . '/no-such-file');
    }

    public function testCheckInvalidJsonFail()
    {
        $this->expectException(InvalidArgumentException::class);
        $checker = $this->getDefaultSecurityChecker();
        $checker->check(json_decode('true'));
    }

    /**
     * NOTE: If this test fails, confirm if there have been more advisories added for the installed packages.
     */
    public function testCheckAll()
    {
        $checker = $this->getDefaultSecurityChecker();
        $vulnerabilities = $checker->check($this->getLockPath());
        $this->assertEqualsCanonicalizing($this->getTestVulnerabilities(), $vulnerabilities);
    }

    /**
     * NOTE: If this test fails, confirm if there have been more advisories added for the installed packages.
     */
    public function testCheckNoDev()
    {
        $checker = $this->getDefaultSecurityChecker();
        $vulnerabilities = $checker->check($this->getLockPath(), false);
        $this->assertEqualsCanonicalizing($this->getTestVulnerabilities(false), $vulnerabilities);
    }

    /**
     * NOTE: If this test fails, confirm if there have been more advisories added for the installed packages.
     */
    public function testCheckAlreadyParsed()
    {
        $checker = $this->getDefaultSecurityChecker();
        $json = json_decode(file_get_contents($this->getLockPath()), true);
        $vulnerabilities = $checker->check($json);
        $this->assertEqualsCanonicalizing($this->getTestVulnerabilities(), $vulnerabilities);
    }

    /**
     * NOTE: If this test fails, confirm if there have been more advisories added for the referenced package.
     */
    public function testPrereleaseVersion()
    {
        $checker = $this->getDefaultSecurityChecker();
        $json = [
            'packages' => [
                [
                    'name' => 'symbiote/silverstripe-queuedjobs',
                    'version' => '4.6.0-rc1',
                ],
            ],
        ];
        $vulnerabilities = $checker->check($json);
        $actual = [
            'symbiote/silverstripe-queuedjobs' => [
                'version' => '4.6.0-rc1',
                'advisories' => [
                    [
                        'title' => 'CVE-2021-27938: XSS in CreateQueuedJobTask',
                        'link' => 'https://www.silverstripe.org/download/security-releases/cve-2021-27938',
                        'cve' => 'CVE-2021-27938',
                    ],
                ],
            ],
        ];
        $this->assertEqualsCanonicalizing($actual, $vulnerabilities);
    }

    private function getDefaultSecurityChecker()
    {
        if (!$this->securityChecker) {
            $this->securityChecker = new SecurityChecker();
        }
        return $this->securityChecker;
    }

    private function getWritableDir()
    {
        return sys_get_temp_dir() . '/security-checker-test';
    }

    private function getLockPath()
    {
        return dirname(__FILE__) . '/composer.lock.test';
    }

     /**
      * Last updated 2021-12-16
      *
      * silverstripe/framework 4.0.0 as a test of direct dependency with its own dependencies with known
      *     vulnerabilities.
      * symbiote/silverstripe-queuedjobs 4.0.x-dev with a specific hash given as a test of dev stabilities
      *     with known vulnerabilities.
      * twig/twig 1.x-dev as a test of a branch with known vulnerabilities, but at a commit after the
      *     vulnerability should no longer apply.
      * phpunit/phpunit 5.0.10 as a test that dev dependencies can be skipped.
      */
    private function getTestVulnerabilities($withDev = true)
    {
        $vulnerabilities = [
            'league/flysystem' => [
                'version' => '1.0.70',
                'advisories' => [
                    [
                        'title' => 'TOCTOU Race Condition enabling remote code execution',
                        'link' => 'https://github.com/thephpleague/flysystem/security/advisories/GHSA-9f46-5r25-5wfm',
                        'cve' => 'CVE-2021-32708',
                    ],
                ],
            ],
            'silverstripe/admin' => [
                'version' => '1.4.5',
                'advisories' => [
                    [
                        'title' => 'CVE-2021-36150 - Insert from files link text - Reflective (self) Cross Site Scripting',
                        'link' => 'https://www.silverstripe.org/download/security-releases/CVE-2021-36150',
                        'cve' => 'CVE-2021-36150',
                    ],
                ],
            ],
            'silverstripe/assets' => [
                'version' => '1.1.0',
                'advisories' => [
                    [
                        'title' => 'CVE-2019-12245: Incorrect access control vulnerability in files uploaded to '
                            . 'protected folders',
                        'link' => 'https://www.silverstripe.org/download/security-releases/cve-2019-12245/',
                        'cve' => 'CVE-2019-12245',
                    ],
                    [
                        'title' => 'CVE-2020-9280: Folders migrated from 3.x may be unsafe to upload to',
                        'link' => 'https://www.silverstripe.org/download/security-releases/cve-2020-9280/',
                        'cve' => 'CVE-2020-9280',
                    ],
                ],
            ],
            'silverstripe/framework' => [
                'version' => '4.0.0',
                'advisories' => [
                    [
                        'title' => 'CVE-2019-12203: Session fixation in "change password" form',
                        'link' => 'https://www.silverstripe.org/download/security-releases/cve-2019-12203/',
                        'cve' => 'CVE-2019-12203',
                    ],
                    [
                        'title' => 'CVE-2019-12246: Denial of Service on flush and development URL tools',
                        'link' => 'https://www.silverstripe.org/download/security-releases/cve-2019-12246',
                        'cve' => 'CVE-2019-12246',
                    ],
                    [
                        'title' => 'CVE-2019-14272: XSS in file titles managed through the CMS',
                        'link' => 'https://www.silverstripe.org/download/security-releases/cve-2019-14272/',
                        'cve' => 'CVE-2019-14272',
                    ],
                    [
                        'title' => 'CVE-2019-14273: Broken Access control on files',
                        'link' => 'https://www.silverstripe.org/download/security-releases/cve-2019-14273/',
                        'cve' => 'CVE-2019-14273',
                    ],
                    [
                        'title' => 'CVE-2019-16409: Secureassets and versionedfiles modules can expose versions of '
                            . 'protected files',
                        'link' => 'https://www.silverstripe.org/download/security-releases/cve-2019-16409/',
                        'cve' => 'CVE-2019-16409',
                    ],
                    [
                        'title' => 'CVE-2019-19325: XSS through non-scalar FormField attributes',
                        'link' => 'https://www.silverstripe.org/download/security-releases/cve-2019-19325/',
                        'cve' => 'CVE-2019-19325',
                    ],
                    [
                        'title' => 'CVE-2019-19326: Web Cache Poisoning through HTTPRequestBuilder',
                        'link' => 'https://www.silverstripe.org/download/security-releases/cve-2019-19326/',
                        'cve' => 'CVE-2019-19326',
                    ],
                    [
                        'title' => 'CVE-2019-5715: Reflected SQL Injection through Form and DataObject',
                        'link' => 'https://www.silverstripe.org/download/security-releases/ss-2018-021',
                        'cve' => 'CVE-2019-5715',
                    ],
                    [
                        'title' => 'CVE-2020-26138 FormField: with square brackets in field name skips validation',
                        'link' => 'https://www.silverstripe.org/download/security-releases/cve-2020-26138',
                        'cve' => 'CVE-2020-26138',
                    ],
                    [
                        'title' => 'CVE-2020-6164: Information disclosure on /interactive URL path',
                        'link' => 'https://www.silverstripe.org/download/security-releases/cve-2020-6164/',
                        'cve' => 'CVE-2020-6164',
                    ],
                    [
                        'title' => 'CVE-2021-25817 XXE: Vulnerability in CSSContentParser',
                        'link' => 'https://www.silverstripe.org/download/security-releases/cve-2021-25817',
                        'cve' => 'CVE-2021-25817',
                    ],
                    [
                        'title' => 'SS-2017-007: CSV Excel Macro Injection',
                        'link' => 'https://www.silverstripe.org/download/security-releases/ss-2017-007/',
                        'cve' => null,
                    ],
                    [
                        'title' => 'SS-2017-008: SQL injection in full text search of SilverStripe 4',
                        'link' => 'https://www.silverstripe.org/download/security-releases/ss-2017-008/',
                        'cve' => null,
                    ],
                    [
                        'title' => 'SS-2017-009: Users inadvertently passing sensitive data to LoginAttempt',
                        'link' => 'https://www.silverstripe.org/download/security-releases/ss-2017-009/',
                        'cve' => null,
                    ],
                    [
                        'title' => 'SS-2017-010: install.php discloses sensitive data by pre-populating DB credential '
                            . 'forms',
                        'link' => 'https://www.silverstripe.org/download/security-releases/ss-2017-010/',
                        'cve' => null,
                    ],
                    [
                        'title' => 'SS-2018-001: Privilege Escalation Risk in Member Edit form',
                        'link' => 'https://www.silverstripe.org/download/security-releases/ss-2018-001/',
                        'cve' => null,
                    ],
                    [
                        'title' => 'SS-2018-005: isDev and isTest unguarded',
                        'link' => 'https://www.silverstripe.org/download/security-releases/ss-2018-005/',
                        'cve' => null,
                    ],
                    [
                        'title' => 'SS-2018-008: BackURL validation bypass with malformed URLs',
                        'link' => 'https://www.silverstripe.org/download/security-releases/ss-2018-008/',
                        'cve' => null,
                    ],
                    [
                        'title' => 'SS-2018-010: Member disclosure in login form',
                        'link' => 'https://www.silverstripe.org/download/security-releases/ss-2018-010/',
                        'cve' => null,
                    ],
                    [
                        'title' => 'SS-2018-012: Uploaded PHP script execution in assets',
                        'link' => 'https://www.silverstripe.org/download/security-releases/ss-2018-012/',
                        'cve' => null,
                    ],
                    [
                        'title' => 'SS-2018-018: Database credentials disclosure during connection failure',
                        'link' => 'https://www.silverstripe.org/download/security-releases/ss-2018-018/',
                        'cve' => null,
                    ],
                    [
                        'title' => 'SS-2018-019: Possible denial of service attack vector when flushing',
                        'link' => 'https://www.silverstripe.org/download/security-releases/ss-2018-019/',
                        'cve' => null,
                    ],
                    [
                        'title' => 'SS-2018-020: Potential SQL vulnerability in PostgreSQL database connector',
                        'link' => 'https://www.silverstripe.org/download/security-releases/ss-2018-020/',
                        'cve' => null,
                    ],
                ],
            ],
            'symbiote/silverstripe-queuedjobs' => [
                'version' => '4.0.x-dev',
                'advisories' => [
                    [
                        'title' => 'CVE-2021-27938: XSS in CreateQueuedJobTask',
                        'link' => 'https://www.silverstripe.org/download/security-releases/cve-2021-27938',
                        'cve' => 'CVE-2021-27938',
                    ],
                ],
            ]
        ];

        if ($withDev) {
            $vulnerabilities = array_merge($vulnerabilities, [
                'phpunit/phpunit' => [
                    'version' => '5.0.10',
                    'advisories' => [
                        [
                            'title' => 'RCE vulnerability in phpunit',
                            'link' => 'https://nvd.nist.gov/vuln/detail/CVE-2017-9841',
                            'cve' => 'CVE-2017-9841',
                        ],
                    ],
                ],
            ]);
        }
        return $vulnerabilities;
    }
}
