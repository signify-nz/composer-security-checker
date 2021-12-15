<?php

namespace Signify\SecurityChecker\Tests;

use PHPUnit\Framework\TestCase;
use Signify\SecurityChecker\StringUtil;

final class StringUtilTest extends TestCase
{
    public const TEST_STRING = 'this is a string to test';

    public function testStartsWith(): void
    {
        // Single string comparison.
        $result = StringUtil::startsWith(self::TEST_STRING, 'this ');
        $this->assertTrue($result);

        // Compare with two strings that match.
        $result = StringUtil::startsWith(self::TEST_STRING, ['this ', 'this is']);
        $this->assertTrue($result);

        // Compare with one string that matches, and one that doesn't.
        $result = StringUtil::startsWith(self::TEST_STRING, ['not start', 'thi']);
        $this->assertTrue($result);

        // Same as above but checking that order doesn't matter.
        $result = StringUtil::startsWith(self::TEST_STRING, ['this is', 'not start']);
        $this->assertTrue($result);

        // Test empty comparator.
        $result = StringUtil::startsWith(self::TEST_STRING, '');
        $this->assertTrue($result);
    }

    public function testDoesntStartWith(): void
    {
        // Single string comparison.
        $result = StringUtil::startsWith(self::TEST_STRING, 'not the start');
        $this->assertFalse($result);

        // Check case sensitivity.
        $result = StringUtil::startsWith(self::TEST_STRING, 'This');
        $this->assertFalse($result);

        // Compare with multiple strings that don't match.
        $result = StringUtil::startsWith(self::TEST_STRING, ['This', 'something else']);
        $this->assertFalse($result);
    }

    public function testEndsWith(): void
    {
        // Single string comparison.
        $result = StringUtil::endsWith(self::TEST_STRING, 'test');
        $this->assertTrue($result);

        // Compare with two strings that match.
        $result = StringUtil::endsWith(self::TEST_STRING, ['test', 'g to test']);
        $this->assertTrue($result);

        // Compare with one string that matches, and one that doesn't.
        $result = StringUtil::endsWith(self::TEST_STRING, ['not end', 'est']);
        $this->assertTrue($result);

        // Same as above but checking that order doesn't matter.
        $result = StringUtil::endsWith(self::TEST_STRING, ['to test', 'not end']);
        $this->assertTrue($result);

        // Test empty comparator.
        $result = StringUtil::endsWith(self::TEST_STRING, '');
        $this->assertTrue($result);
    }

    public function testDoesntEndWith(): void
    {
        // Single string comparison.
        $result = StringUtil::endsWith(self::TEST_STRING, 'not the end');
        $this->assertFalse($result);

        // Check case sensitivity.
        $result = StringUtil::endsWith(self::TEST_STRING, 'Test');
        $this->assertFalse($result);

        // Compare with multiple strings that don't match.
        $result = StringUtil::endsWith(self::TEST_STRING, ['Test', 'something else']);
        $this->assertFalse($result);
    }

    public function testRemoveFromStart(): void
    {
        // Remove a single string.
        $result = StringUtil::removeFromStart(self::TEST_STRING, 'this is');
        $this->assertSame(' a string to test', $result);

        // Remove multiple strings in succession.
        $result = StringUtil::removeFromStart(self::TEST_STRING, ['this is', ' a string ']);
        $this->assertSame('to test', $result);

        // Check that the strings are removed in order.
        $result = StringUtil::removeFromStart(self::TEST_STRING, ['this is', 'this is a ']);
        $this->assertSame(' a string to test', $result);

        // Check that only strings that fully match are removed (no removal by strlen if no match).
        $result = StringUtil::removeFromStart(self::TEST_STRING, ['this match', 'this ']);
        $this->assertSame('is a string to test', $result);
    }

    public function testDontRemoveFromStart(): void
    {
        // Don't remove a single string when it doesn't match.
        $result = StringUtil::removeFromStart(self::TEST_STRING, 'to test');
        $this->assertSame(self::TEST_STRING, $result);

        // Don't remove any strings when they don't match.
        $result = StringUtil::removeFromStart(self::TEST_STRING, ['to test', ' a string ']);
        $this->assertSame(self::TEST_STRING, $result);

        // Make sure nothing weird happens with empty string comparators.
        $result = StringUtil::removeFromStart(self::TEST_STRING, '');
        $this->assertSame(self::TEST_STRING, $result);
    }

    public function testRemoveFromEnd(): void
    {
        // Remove a single string.
        $result = StringUtil::removeFromEnd(self::TEST_STRING, 'to test');
        $this->assertSame('this is a string ', $result);

        // Remove multiple strings in succession.
        $result = StringUtil::removeFromEnd(self::TEST_STRING, ['to test', ' a string ']);
        $this->assertSame('this is', $result);

        // Check that the strings are removed in order.
        $result = StringUtil::removeFromEnd(self::TEST_STRING, ['to test', 'string to test']);
        $this->assertSame('this is a string ', $result);

        // Check that only strings that fully match are removed (no removal by strlen if no match).
        $result = StringUtil::removeFromEnd(self::TEST_STRING, ['match test', ' test']);
        $this->assertSame('this is a string to', $result);
    }

    public function testDontRemoveFromEnd(): void
    {
        // Don't remove a single string when it doesn't match.
        $result = StringUtil::removeFromEnd(self::TEST_STRING, 'this is');
        $this->assertSame(self::TEST_STRING, $result);

        // Don't remove any strings when they don't match.
        $result = StringUtil::removeFromEnd(self::TEST_STRING, ['this is', ' a string ']);
        $this->assertSame(self::TEST_STRING, $result);

        // Make sure nothing weird happens with empty string comparators.
        $result = StringUtil::removeFromEnd(self::TEST_STRING, '');
        $this->assertSame(self::TEST_STRING, $result);
    }
}
