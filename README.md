# Composer Security Checker
Inspired by [sensiolabs/security-checker](https://github.com/sensiolabs/security-checker) and [fabpot/local-php-security-checker](https://github.com/fabpot/local-php-security-checker).

The Composer Security Checker provides an API for checking if your PHP application has dependencies with known security vulnerabilities. If uses the [PHP Security Advisories Database](https://github.com/FriendsOfPHP/security-advisories) - the same database used by [fabpot/local-php-security-checker](https://github.com/fabpot/local-php-security-checker) and the [Symfony CLI](https://symfony.com/doc/current/setup.html#security-checker).

It can be useful, for example, for applications that have a dashboard where you can display a clear warning if vulnerabilities are detected.

## Install
Install via [composer](https://getcomposer.org):

```bash
composer require signify-nz/composer-security-checker
```

## Usage
Simply instantiate a `SecurityChecker` object and pass the absolute path to your `composer.lock` file in a call to `check` and it will return an array of vulnerabilities that apply to the dependencies of that lock file.
```php
use Signify\SecurityChecker\SecurityChecker;
$checker = new SecurityChecker();
$vulnerabilities = $checker->check('/path/to/composer.lock');
```

If you have already parsed the `composer.lock` file into an associative array, you can pass that to the call to `check` instead:
```php
use Signify\SecurityChecker\SecurityChecker;
$checker = new SecurityChecker();
$composerLockArray = json_decode(file_get_contents('/path/to/composer.lock'), true);
$vulnerabilities = $checker->check($composerLockArray);
```

### Configuration Options
There are some configuration options you can pass into the constructor to determine how the checker behaves.
```php
use Signify\SecurityChecker\SecurityChecker;
$options = [
    /* Set your configuration using below options */
];
$checker = new SecurityChecker($options);
$vulnerabilities = $checker->check('/path/to/composer.lock');
```

The options you can set are listed in this table.
| Option name | Purpose | Value type | Default |
| ----------- | ------- | ---------- | ------- |
| advisories-dir | A writable directory to store the PHP Security Advisories Database | string | A temporary directory (uses [sys_get_temp_dir](https://www.php.net/manual/en/function.sys-get-temp-dir.php)) |
| advisories-stale-after | Time in seconds that the stored advisories database is valid - it will be fetched again after this time expires. | int | `86400` (24 hours) |
| include-dev-packages | Whether to include dev packages when checking for security vulnerabilities | boolean | `true` |
| guzzle-options | Options to pass to the Guzzle client when fetching the advisories database. See [the guzzle docs](https://docs.guzzlephp.org/en/stable/request-options.html) for options. | array | `[]` |
