/*
 * Copyright 2025 Katatsumuri_pan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.k_pan.ssdeep4j;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class FuzzyComparatorTest {

	// Test cases from the original ssdeep library and other known vectors.
	@ParameterizedTest
	@CsvSource({
			// Identical hashes
			"'48:abcdefg:abcdefg', '48:abcdefg:abcdefg', 100",
			"'192:A95DD4484A95DD4484A95DD4484:15d44d5d44d5d44d', '192:A95DD4484A95DD4484A95DD4484:15d44d5d44d5d44d', 100",

			// Different block sizes but related
			"'48:abcdefg:abcdefg', '96:hijklmn:hijklmn', 0",

			// Similar hashes (length >= 7)
			"'48:abcdefgh:abcdefgh', '48:abcdefgi:abcdefgi', 88",
			"'96:ThisIsATestString1:ThisIsATestString1', '96:ThisIsATestString2:ThisIsATestString2', 96",

			// Completely different hashes
			"'48:abcdefg:abcdefg', '48:hijklmn:hijklmn', 0",

			// Hashes with no common substring
			"'6:abcdefg:abcdefg', '6:hijklmn:hijklmn', 0",
	})
	void testCompareValidHashes(String hash1, String hash2, int expectedScore) {
		assertEquals(expectedScore, FuzzyComparator.compare(hash1, hash2));
	}

	@ParameterizedTest
	@CsvSource({
			"'3:h', '3:h:h'",
			"'3:h:h', '3:h'",
			"'abc:h:h', '3:h:h'",
			"'3:h:h', 'abc:h:h'",
			"':h:h', '3:h:h'",
	})
	void testCompareMalformedHashes(String hash1, String hash2) {
		assertEquals(-1, FuzzyComparator.compare(hash1, hash2));
	}

	@Test
	void testCompareWithNull() {
		String hash = "3:h:h";
		assertEquals(-1, FuzzyComparator.compare(hash, null));
		assertEquals(-1, FuzzyComparator.compare(null, hash));
		assertEquals(-1, FuzzyComparator.compare(null, null));
	}

	@ParameterizedTest
	@CsvSource({
			// Incompatible block sizes
			"'3:h:h', '5:v:v', 0",
			"'48:cJN6o:cJN6o', '128:HDEHDGAy2:HDEHDGAy2', 0",
	})
	void testCompareIncompatibleBlockSizes(String hash1, String hash2, int expectedScore) {
		assertEquals(expectedScore, FuzzyComparator.compare(hash1, hash2));
	}

	@Test
	void testLongHashesComparison() {
		// These strings are longer than 64 characters and do not contain repeating sequences
		// that would be eliminated. This ensures the Wagner-Fischer algorithm is tested.
		String part1 = "abc".repeat(22); // length 66
		String part2 = "abc".repeat(21) + "add"; // length 66, two characters difference

		String longHash1 = "1536:" + part1 + ":" + part1;
		String longHash2 = "1536:" + part2 + ":" + part2;

		assertEquals(99, FuzzyComparator.compare(longHash1, longHash2));
	}

	@ParameterizedTest
	@CsvSource({
			// One or both parts are shorter than ROLLING_WINDOW (7)
			"'3:abcdef:abcdef', '3:abcdefg:abcdefg', 0",
			"'3:abc:abc', '3:def:def', 0",
			"'48:short1:longenough1', '48:short2:longenough2', 93",
			"'3:abc:abc', '3:abc:abc', 100",
	})
	void testCompareShortHashParts(String hash1, String hash2, int expectedScore) {
		assertEquals(expectedScore, FuzzyComparator.compare(hash1, hash2));
	}
}
