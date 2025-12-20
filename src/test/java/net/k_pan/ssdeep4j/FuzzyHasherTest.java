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
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;

class FuzzyHasherTest {

	private static final String TEST_STRING = "Hello, ssdeep4j! This is a test string for fuzzy hashing.";
	private static final String TEST_STRING_HASH = "3:a62AVpAFVEpFZgMFMEFZL:aELAFurNFME3";

	@Test
	void testHashFromFile(@TempDir Path tempDir) throws IOException {
		Path testFile = tempDir.resolve("testfile.txt");
		Files.writeString(testFile, TEST_STRING);

		String actualHash = FuzzyHasher.hash(testFile);

		assertEquals(TEST_STRING_HASH, actualHash);
	}

	@Test
	void testHashFromBytes() throws IOException {
		byte[] content = TEST_STRING.getBytes(StandardCharsets.UTF_8);

		String actualHash = FuzzyHasher.hash(content);

		assertEquals(TEST_STRING_HASH, actualHash);
	}

	@Test
	void testHashFromInputStream() throws IOException {
		byte[] content = TEST_STRING.getBytes(StandardCharsets.UTF_8);
		try (InputStream is = new ByteArrayInputStream(content)) {
			String actualHash = FuzzyHasher.hash(is);
			assertEquals(TEST_STRING_HASH, actualHash);
		}
	}

	@Test
	void testFuzzyStateChunkedUpdate() throws IOException {
		FuzzyHasher.FuzzyState state = new FuzzyHasher.FuzzyState();
		byte[] content = TEST_STRING.getBytes(StandardCharsets.UTF_8);

		// Split data into three chunks
		int chunkSize = content.length / 3;
		byte[] chunk1 = new byte[chunkSize];
		byte[] chunk2 = new byte[chunkSize];
		byte[] chunk3 = new byte[content.length - 2 * chunkSize];

		System.arraycopy(content, 0, chunk1, 0, chunkSize);
		System.arraycopy(content, chunkSize, chunk2, 0, chunkSize);
		System.arraycopy(content, 2 * chunkSize, chunk3, 0, chunk3.length);

		state.engineUpdate(new ByteArrayInputStream(chunk1));
		state.engineUpdate(new ByteArrayInputStream(chunk2));
		state.engineUpdate(new ByteArrayInputStream(chunk3));

		String actualHash = state.digest();
		assertEquals(TEST_STRING_HASH, actualHash);
	}

	@Test
	void testSetTotalInputLength() throws IOException {
		byte[] content = TEST_STRING.getBytes(StandardCharsets.UTF_8);
		FuzzyHasher.FuzzyState state = new FuzzyHasher.FuzzyState();

		assertEquals(0, state.setTotalInputLength(content.length));

		state.engineUpdate(new ByteArrayInputStream(content));

		String actualHash = state.digest();
		assertEquals(TEST_STRING_HASH, actualHash);
	}

	@ParameterizedTest
	@CsvSource({
			"'', '3::'",
			"'a', '3:E:E'",
			"'abc', '3:uG:uG'",
			"'abcdef', '3:uj:uj'",
			"'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX', '3:XV9999999999999999999999999999999999999999999n:f'",
	})
	void testTextInputs1(String input, String expectedHash) throws IOException {
		byte[] content = input.getBytes(StandardCharsets.UTF_8);
		String actualHash = FuzzyHasher.hash(content);
		assertEquals(expectedHash, actualHash);
	}

	@Test
	void testTextInput2() throws IOException {
		String longText = "The ssdeep project is a project to compute context triggered "
				+ "piecewise hashes (CTPH). Also called fuzzy hashes. CTPH can match "
				+ "inputs that have homologies. Such inputs have sequences of identical "
				+ "bytes in the same order, although bytes in between these sequences "
				+ "may be different in content and length.";
		String expectedHash = "6:HQMxlNqD8ZczN0WthxLsr2GOMeMBfYZXQpdamb:wMxlNpZcKqhNO2RKBfYFQpdr";
		String actualHash = FuzzyHasher.hash(longText.getBytes(StandardCharsets.UTF_8));
		assertEquals(expectedHash, actualHash);
	}

	@Test
	void testNullByteInput() throws IOException {
		byte[] nullBytes = new byte[256]; // All bytes are 0x00
		String expectedHash = "3::";
		String actualHash = FuzzyHasher.hash(nullBytes);
		assertEquals(expectedHash, actualHash);
	}

	@Test
	void testRandomBinaryInput1() throws IOException {
		byte[] randomBytes = new byte[8192];
		new Random(12345).nextBytes(randomBytes); // Use a fixed seed for reproducibility
		String expectedHash = "96:Vj/7ZQN0RSmW2nr5fMNrLAVN9yGvFB/7VzE0ODPZc9dvGxQBDGKfg1goxexrCLwC:Vj/7WN0kmW2nlC+Zz+TSf6sxOkuV";
		String actualHash = FuzzyHasher.hash(randomBytes);
		assertEquals(expectedHash, actualHash);
	}

	@Test
	void testRandomBinaryInput2() throws IOException {
		byte[] randomBytes = new byte[1024 * 1024];
		new Random(99999).nextBytes(randomBytes); // Use a fixed seed for reproducibility
		String expectedHash = "24576:xiX3sxju0GrsNm+SwNtrIFaBD6SU/2OBGLqLL:O3Qju/QkTwNNII6fnE0L";
		String actualHash = FuzzyHasher.hash(randomBytes);
		assertEquals(expectedHash, actualHash);
	}

	@ParameterizedTest
	@CsvSource({
			// No sequences
			"abcdefg, abcdefg",
			// Sequence of 3 (no change)
			"aaabcdef, aaabcdef",
			// Sequence of 4
			"aaaabcdef, aaabcdef",
			// Sequence of 5
			"aaaaabcdef, aaabcdef",
			// Multiple sequences
			"aaaabbbcccccdef, aaabbbcccdef",
			// Sequence at the beginning
			"dddddef, dddef",
			// Sequence in the middle
			"abcdeeeefgh, abcdeeefgh",
			// Sequence at the end
			"abcdeffff, abcdefff",
			// Null input
			",",
			// Empty string
			"'', ''"
	})
	void testCopyEliminateSequences(String input, String expected) {
		assertEquals(expected, FuzzyHasher.copyEliminateSequences(input));
		StringBuilder sb = new StringBuilder();
		if (input != null) {
			FuzzyHasher.appendEliminateSequences(sb, input.toCharArray(), 0, input.length());
			assertEquals(expected, sb.toString());
		}
	}
}
