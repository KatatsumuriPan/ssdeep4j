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

/**
 * Represents a fuzzy hash, providing methods for comparison.
 * <p>
 * This class encapsulates the components of a fuzzy hash (block size and block strings)
 * and offers an optimized way to compare it against other fuzzy hashes.
 * It pre-processes the hash string to avoid redundant parsing during repeated comparisons.
 * <p>
 * Example usage:
 * <pre>
 * FuzzyHash hash1 = new FuzzyHash(hashString1);
 * FuzzyHash hash2 = new FuzzyHash(hashString2);
 * int score = hash1.compare(hash2);
 * </pre>
 *
 * @since 1.2.0
 */
public class FuzzyHash {

	private final long blockSize;
	private final String block1;
	private final String block2;

	/**
	 * Constructs a new FuzzyHash from the given hash string.
	 *
	 * @param hashString The fuzzy hash string.
	 * @throws IllegalArgumentException If the hash string is null or malformed.
	 */
	public FuzzyHash(String hashString) {
		if (hashString == null) {
			throw new IllegalArgumentException("Hash string cannot be null");
		}

		int p1 = hashString.indexOf(':');
		int p2 = (p1 == -1) ? -1 : hashString.indexOf(':', p1 + 1);

		if (p2 == -1) {
			throw new IllegalArgumentException("Invalid fuzzy hash format: " + hashString);
		}

		long parsedBlockSize;
		try {
			parsedBlockSize = JavaCompat.parseLong(hashString, 0, p1);
		} catch (NumberFormatException e) {
			throw new IllegalArgumentException("Invalid block size in fuzzy hash: " + hashString, e);
		}

		this.blockSize = parsedBlockSize;
		this.block1 = FuzzyHasher.copyEliminateSequences(hashString.substring(p1 + 1, p2));
		this.block2 = FuzzyHasher.copyEliminateSequences(hashString.substring(p2 + 1));
	}

	/**
	 * Package-private constructor for efficient instantiation from FuzzyHasher.
	 * Assumes that block1 and block2 are already processed (sequences eliminated).
	 */
	FuzzyHash(long blockSize, String block1, String block2) {
		this.blockSize = blockSize;
		this.block1 = block1;
		this.block2 = block2;
	}

	public long getBlockSize() {
		return blockSize;
	}

	public String getBlock1() {
		return block1;
	}

	public String getBlock2() {
		return block2;
	}

	/**
	 * Compares this fuzzy hash with another fuzzy hash string.
	 *
	 * @param otherHashString The fuzzy hash string to compare against.
	 * @return <ul>
	 * <li>A similarity score between 0 and 100 (100 indicates a perfect match).</li>
	 * <li>-1 if the other hash string is null or malformed.</li>
	 * <li>0 if the block sizes are incompatible for comparison.</li>
	 * </ul>
	 */
	public int compare(String otherHashString) {
		return FuzzyComparator.compare(this, otherHashString);
	}

	/**
	 * Compares this fuzzy hash with another FuzzyHash object.
	 *
	 * @param other The FuzzyHash object to compare against.
	 * @return <ul>
	 * <li>A similarity score between 0 and 100 (100 indicates a perfect match).</li>
	 * <li>-1 if the other object is null.</li>
	 * <li>0 if the block sizes are incompatible for comparison.</li>
	 * </ul>
	 */
	public int compare(FuzzyHash other) {
		return FuzzyComparator.compare(this, other);
	}

	@Override
	public String toString() {
		return blockSize + ":" + block1 + ":" + block2;
	}
}
