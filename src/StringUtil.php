<?php

namespace Signify\SecurityChecker;

final class StringUtil
{
    /**
     * Check whether some string starts with some other string.
     *
     * @param string $haystack String to check.
     * @param string[]|string $needles A string or list of strings to check against.
     * @return boolean Returns true if the haystack starts with any one of the needles.
     */
    public static function startsWith(string $haystack, $needles): bool
    {
        if (!is_array($needles)) {
            $needles = [$needles];
        }
        foreach ($needles as $needle) {
            if (!strlen($needle) || strpos($haystack, $needle) === 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check whether some string ends with some other string.
     *
     * @param string $haystack String to check.
     * @param string[]|string $needles A string or list of strings to check against.
     * @return boolean Returns true if the haystack ends with any one of the needles.
     */
    public static function endsWith(string $haystack, $needles): bool
    {
        if (!is_array($needles)) {
            $needles = [$needles];
        }
        foreach ($needles as $needle) {
            $length = strlen($needle);
            if (!$length || substr($haystack, -$length) === $needle) {
                return true;
            }
        }
        return false;
    }

    /**
     * Remove some strings from the start of some other string.
     *
     * @param string $haystack Original string.
     * @param string[]|string $needles A string or list of strings to remove.
     * @return string The new string.
     */
    public static function removeFromStart(string $haystack, $needles): string
    {
        if (!is_array($needles)) {
            $needles = [$needles];
        }
        foreach ($needles as $needle) {
            if (self::startsWith($haystack, $needle)) {
                $toRemoveLength = strlen($needle);
                $newLength = strlen($haystack) - $toRemoveLength;
                $haystack = substr($haystack, $toRemoveLength, $newLength);
            }
        }
        return $haystack;
    }

    /**
     * Remove some strings from the end of some other string.
     *
     * @param string $haystack Original string.
     * @param string[]|string $needles A string or list of strings to remove.
     * @return string The new string.
     */
    public static function removeFromEnd(string $haystack, $needles): string
    {
        if (!is_array($needles)) {
            $needles = [$needles];
        }
        foreach ($needles as $needle) {
            if (self::endsWith($haystack, $needle)) {
                $newLength = strlen($haystack) - strlen($needle);
                $haystack = substr($haystack, 0, $newLength);
            }
        }
        return $haystack;
    }
}
