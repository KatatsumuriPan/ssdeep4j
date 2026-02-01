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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;

class FuzzyHashTest {

	@ParameterizedTest
	@CsvSource({
			// Identical hashes
			"'48:abcdefg:abcdefg', '48:abcdefg:abcdefg', 100",
			"'192:A95DD4484A95DD4484A95DD4484:15d44d5d44d5d44d', '192:A95DD4484A95DD4484A95DD4484:15d44d5d44d5d44d', 100",

			// Similar hashes (length >= 7)
			"'48:abcdefgh:abcdefgh', '48:abcdefgi:abcdefgi', 88",
			"'96:ThisIsATestString1:ThisIsATestString1', '96:ThisIsATestString2:ThisIsATestString2', 96",

			// Completely different hashes
			"'48:abcdefg:abcdefg', '48:hijklmn:hijklmn', 0",

			// Hashes with no common substring
			"'6:abcdefg:abcdefg', '6:hijklmn:hijklmn', 0",

			// Different block sizes but related (should result in 0 if not compatible)
			"'48:abcdefg:abcdefg', '96:hijklmn:hijklmn', 0", // Incompatible block sizes, should be 0

			// Incompatible block sizes (from FuzzyComparatorTest)
			"'3:h:h', '5:v:v', 0",
			"'48:cJN6o:cJN6o', '128:HDEHDGAy2:HDEHDGAy2', 0",

			// Short hash parts (from FuzzyComparatorTest)
			"'3:abcdef:abcdef', '3:abcdefg:abcdefg', 0", // One part shorter than ROLLING_WINDOW
			"'3:abc:abc', '3:def:def', 0", // Both parts shorter
			"'48:short1:longenough1', '48:short2:longenough2', 93", // One short, one long
			"'3:abc:abc', '3:abc:abc', 100", // Identical short hashes
	})
	void testCompareHashesWithString(String hash1, String hash2, int expectedScore) {
		FuzzyHash fuzzyHash1 = new FuzzyHash(hash1);
		assertEquals(expectedScore, fuzzyHash1.compare(hash2));
	}

	@ParameterizedTest
	@CsvSource({
			// Identical hashes
			"'48:abcdefg:abcdefg', '48:abcdefg:abcdefg', 100",
			"'192:A95DD4484A95DD4484A95DD4484:15d44d5d44d5d44d', '192:A95DD4484A95DD4484A95DD4484:15d44d5d44d5d44d', 100",

			// Similar hashes (length >= 7)
			"'48:abcdefgh:abcdefgh', '48:abcdefgi:abcdefgi', 88",
			"'96:ThisIsATestString1:ThisIsATestString1', '96:ThisIsATestString2:ThisIsATestString2', 96",

			// Completely different hashes
			"'48:abcdefg:abcdefg', '48:hijklmn:hijklmn', 0",

			// Hashes with no common substring
			"'6:abcdefg:abcdefg', '6:hijklmn:hijklmn', 0",

			// Different block sizes but related (should result in 0 if not compatible)
			"'48:abcdefg:abcdefg', '96:hijklmn:hijklmn', 0", // Incompatible block sizes, should be 0

			// Incompatible block sizes (from FuzzyComparatorTest)
			"'3:h:h', '5:v:v', 0",
			"'48:cJN6o:cJN6o', '128:HDEHDGAy2:HDEHDGAy2', 0",

			// Short hash parts (from FuzzyComparatorTest)
			"'3:abcdef:abcdef', '3:abcdefg:abcdefg', 0", // One part shorter than ROLLING_WINDOW
			"'3:abc:abc', '3:def:def', 0", // Both parts shorter
			"'48:short1:longenough1', '48:short2:longenough2', 93", // One short, one long
			"'3:abc:abc', '3:abc:abc', 100", // Identical short hashes
	})
	void testCompareHashesWithFuzzyHashObject(String hash1, String hash2, int expectedScore) {
		FuzzyHash fuzzyHash1 = new FuzzyHash(hash1);
		FuzzyHash fuzzyHash2 = new FuzzyHash(hash2);
		assertEquals(expectedScore, fuzzyHash1.compare(fuzzyHash2));
	}

	@Test
	void testConstructorCallsCopyEliminateSequences() {
		String targetHash = "48:block1:block2";

		try (MockedStatic<FuzzyHasher> mockedHasher = mockStatic(FuzzyHasher.class)) {
			// Setup mock behavior
			mockedHasher.when(() -> FuzzyHasher.copyEliminateSequences("block1")).thenReturn("normalized1");
			mockedHasher.when(() -> FuzzyHasher.copyEliminateSequences("block2")).thenReturn("normalized2");

			new FuzzyHash(targetHash);

			// Verify calls
			mockedHasher.verify(() -> FuzzyHasher.copyEliminateSequences("block1"), times(1));
			mockedHasher.verify(() -> FuzzyHasher.copyEliminateSequences("block2"), times(1));
		}
	}

	@ParameterizedTest
	@ValueSource(strings = {
			"3:h",
			"abc:h:h",
			":h:h",
			"invalid"
	})
	void testConstructorWithInvalidHash(String invalidHash) {
		assertThrows(IllegalArgumentException.class, () -> new FuzzyHash(invalidHash));
	}

	@Test
	void testConstructorWithNull() {
		assertThrows(IllegalArgumentException.class, () -> new FuzzyHash(null));
	}

	@Test
	void testCompareWithNullArguments() {
		FuzzyHash fuzzyHash = new FuzzyHash("48:test:test");
		assertEquals(-1, fuzzyHash.compare((String) null));
		assertEquals(-1, fuzzyHash.compare((FuzzyHash) null));
	}

	@Test
	void testCompareWithMalformedStringHash() {
		FuzzyHash fuzzyHash = new FuzzyHash("48:test:test");
		assertEquals(-1, fuzzyHash.compare("invalid"));
		assertEquals(-1, fuzzyHash.compare("48:block1"));
		assertEquals(-1, fuzzyHash.compare("abc:block1:block2")); // Invalid block size
	}

	@Test
	void testLongHashesComparisonDelegation() {
		// These strings are longer than 64 characters and do not contain repeating sequences
		// that would be eliminated. This ensures the Wagner-Fischer algorithm is tested
		// via FuzzyComparator.
		String part1 = "abc".repeat(22); // length 66
		String part2 = "abc".repeat(21) + "add"; // length 66, two characters difference

		String longHash1 = "1536:" + part1 + ":" + part1;
		String longHash2 = "1536:" + part2 + ":" + part2;

		FuzzyHash fh1 = new FuzzyHash(longHash1);
		FuzzyHash fh2 = new FuzzyHash(longHash2);

		// This test now relies on FuzzyComparator.compare to return the correct score.
		// The actual score (99) is verified in FuzzyComparatorTest.
		assertEquals(99, fh1.compare(fh2));
		assertEquals(99, fh1.compare(longHash2));
	}
}
