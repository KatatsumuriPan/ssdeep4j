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

import java.util.HashSet;
import java.util.Set;

/**
 * A Java implementation of the ssdeep fuzzy hash comparison algorithm.
 * <p>
 * This utility class provides static methods to compare two ssdeep fuzzy hashes and
 * calculate a similarity score from 0 (no similarity) to 100 (identical).
 * The implementation is based on the logic in the original C version of ssdeep.
 * <p>
 * This class is non-instantiable and its methods are thread-safe.
 *
 * @see <a href="https://github.com/ssdeep-project/ssdeep/blob/master/fuzzy.c">ssdeep fuzzy.c</a>
 */
public final class FuzzyComparator {

	/**
	 * The maximum length of the second block (block2) of an ssdeep hash.
	 * The first block (block1) has a maximum length of {@code SPAMSUM_LENGTH / 2}.
	 */
	static final int SPAMSUM_LENGTH = 64;

	/**
	 * The minimum block size used in the ssdeep algorithm.
	 */
	static final int MIN_BLOCKSIZE = 3;

	private static final int MIN_CHAR = '+';
	private static final int MAX_CHAR = 'z';
	private static final int MASK_ARRAY_SIZE = MAX_CHAR - MIN_CHAR + 1;

	/**
	 * Non-instantiable utility class.
	 */
	private FuzzyComparator() {
	}

	/**
	 * Compares two fuzzy hash strings and returns a similarity score from 0 to 100.
	 *
	 * @param hash1 The first fuzzy hash string to compare.
	 * @param hash2 The second fuzzy hash string to compare.
	 * @return <ul>
	 * <li>A similarity score between 0 and 100 (100 indicates a perfect match).</li>
	 * <li>-1 if either hash string is null or malformed.</li>
	 * <li>0 if the block sizes are incompatible for comparison.</li>
	 * </ul>
	 */
	public static int compare(String hash1, String hash2) {
		if (hash1 == null || hash2 == null) {
			return -1;
		}

		int p1c1 = hash1.indexOf(':');
		int p1c2 = (p1c1 == -1) ? -1 : hash1.indexOf(':', p1c1 + 1);
		int p2c1 = hash2.indexOf(':');
		int p2c2 = (p2c1 == -1) ? -1 : hash2.indexOf(':', p2c1 + 1);

		if (p1c2 == -1 || p2c2 == -1) {
			return -1;
		}

		long blockSize1, blockSize2;
		try {
			blockSize1 = JavaCompat.parseLong(hash1, 0, p1c1);
			blockSize2 = JavaCompat.parseLong(hash2, 0, p2c1);
		} catch (NumberFormatException e) {
			return -1;
		}

		// Block sizes must be related to be comparable.
		if (!areBlockSizesCompatible(blockSize1, blockSize2)) {
			return 0;
		}

		String s1b1 = FuzzyHasher.copyEliminateSequences(hash1.substring(p1c1 + 1, p1c2));
		String s1b2 = FuzzyHasher.copyEliminateSequences(hash1.substring(p1c2 + 1));
		String s2b1 = FuzzyHasher.copyEliminateSequences(hash2.substring(p2c1 + 1, p2c2));
		String s2b2 = FuzzyHasher.copyEliminateSequences(hash2.substring(p2c2 + 1));

		return compareParsed(blockSize1, s1b1, s1b2, blockSize2, s2b1, s2b2);
	}

	/**
	 * Compares a FuzzyHash object with a fuzzy hash string and returns a similarity score from 0 to 100.
	 *
	 * @param hash1 The FuzzyHash object.
	 * @param hash2 The fuzzy hash string.
	 * @return <ul>
	 * <li>A similarity score between 0 and 100 (100 indicates a perfect match).</li>
	 * <li>-1 if the FuzzyHash object is null or the hash string is null/malformed.</li>
	 * <li>0 if the block sizes are incompatible for comparison.</li>
	 * </ul>
	 * @since 1.2.0
	 */
	public static int compare(FuzzyHash hash1, String hash2) {
		if (hash1 == null || hash2 == null) {
			return -1;
		}

		int p1 = hash2.indexOf(':');
		int p2 = (p1 == -1) ? -1 : hash2.indexOf(':', p1 + 1);

		if (p2 == -1) {
			return -1;
		}

		long blockSize1 = hash1.getBlockSize();
		long blockSize2;
		try {
			blockSize2 = JavaCompat.parseLong(hash2, 0, p1);
		} catch (NumberFormatException e) {
			return -1;
		}

		// Block sizes must be related to be comparable.
		if (!areBlockSizesCompatible(blockSize1, blockSize2)) {
			return 0;
		}

		String s2b1 = FuzzyHasher.copyEliminateSequences(hash2.substring(p1 + 1, p2));
		String s2b2 = FuzzyHasher.copyEliminateSequences(hash2.substring(p2 + 1));

		return compareParsed(blockSize1, hash1.getBlock1(), hash1.getBlock2(),
				blockSize2, s2b1, s2b2);
	}

	/**
	 * Compares two FuzzyHash objects and returns a similarity score from 0 to 100.
	 *
	 * @param h1 The first FuzzyHash object.
	 * @param h2 The second FuzzyHash object.
	 * @return <ul>
	 * <li>A similarity score between 0 and 100 (100 indicates a perfect match).</li>
	 * <li>-1 if either FuzzyHash object is null.</li>
	 * <li>0 if the block sizes are incompatible for comparison.</li>
	 * </ul>
	 * @since 1.2.0
	 */
	public static int compare(FuzzyHash h1, FuzzyHash h2) {
		if (h1 == null || h2 == null) {
			return -1;
		}

		// Block sizes must be related to be comparable for pre-parsed hashes.
		if (!areBlockSizesCompatible(h1.getBlockSize(), h2.getBlockSize())) {
			return 0;
		}
		return compareParsed(h1.getBlockSize(), h1.getBlock1(), h1.getBlock2(),
				h2.getBlockSize(), h2.getBlock1(), h2.getBlock2());
	}

	static boolean areBlockSizesCompatible(long blockSize1, long blockSize2) {
		return blockSize1 == blockSize2 || (blockSize1 * 2 == blockSize2) || (blockSize1 / 2 == blockSize2);
	}

	/**
	 * Calculates a similarity score between two hash parts (strings).
	 * <p>
	 * This is a helper method for the main {@link #compare(String, String)} function.
	 * It returns 0 if either string is shorter than the rolling window size, as a meaningful
	 * comparison is not possible.
	 *
	 * @param s1        The first string.
	 * @param s2        The second string.
	 * @param blockSize The block size associated with the strings, used for score adjustment.
	 * @return The calculated similarity score, or 0 if strings are too short.
	 */
	static int scoreStrings(String s1, String s2, long blockSize) {
		if (s1.length() < RollState.ROLLING_WINDOW || s2.length() < RollState.ROLLING_WINDOW) {
			return 0;
		}

		if (s1.length() > s2.length()) {
			String temp = s1;
			s1 = s2;
			s2 = temp;
		}

		int dist;
		if (s1.length() <= 64) {
			long[] patternMask = new long[MASK_ARRAY_SIZE];
			for (int i = 0; i < s1.length(); i++) {
				patternMask[s1.charAt(i) - MIN_CHAR] |= (1L << i);
			}
			if (!hasCommonSubstringBitmask(patternMask, s2)) {
				return 0;
			}
			dist = editDistanceBitParallel(patternMask, s1.length(), s2);
		} else {
			if (!hasCommonSubstringRolling(s1, s2)) {
				return 0;
			}
			dist = editDistanceWagnerFischer(s1, s2);
		}

		// Normalize the score based on the edit distance and string lengths.
		int score = (dist * SPAMSUM_LENGTH) / (s1.length() + s2.length());
		score = (100 * score) / SPAMSUM_LENGTH;
		score = 100 - score;

		// Adjust the score based on the block size.
		if (blockSize >= (99 + RollState.ROLLING_WINDOW) / RollState.ROLLING_WINDOW * MIN_BLOCKSIZE)
			return score;
		long term_score = blockSize / MIN_BLOCKSIZE * s1.length();
		return (int) Math.min(score, term_score);
	}

	/**
	 * Determines if two short strings (<= 64 chars) share a common substring of length
	 * {@link RollState#ROLLING_WINDOW} using a bitmasking algorithm.
	 *
	 * @param patternMask The pre-computed pattern bitmask for s1.
	 * @param s2          The second string (text).
	 * @return {@code true} if a common substring is found, {@code false} otherwise.
	 */
	static boolean hasCommonSubstringBitmask(long[] patternMask, String s2) {

		int s2len = s2.length();
		long D;
		// ROLLING_WINDOW <= s2len <= 64
		int r = RollState.ROLLING_WINDOW - 1;
		int l;
		int chIdx;
		while (r < s2len) {
			l = r - (RollState.ROLLING_WINDOW - 1);
			chIdx = s2len - 1 - r;
			D = patternMask[s2.charAt(chIdx) - MIN_CHAR];
			while (D != 0) {
				r--;
				D = (D << 1) & patternMask[s2.charAt(++chIdx) - MIN_CHAR];
				if (r == l && D != 0)
					return true;
			}
			// Boyer-Moore-like skipping
			r += RollState.ROLLING_WINDOW;
		}
		return false;
	}

	/**
	 * Determines if two strings share a common substring of length {@link RollState#ROLLING_WINDOW}.
	 * <p>
	 * This method serves as a fast pre-check to avoid expensive edit distance calculations
	 * for strings that are clearly dissimilar. It uses a rolling hash to efficiently find
	 * potential common substrings, which are then verified to handle hash collisions.
	 *
	 * @param s1 The first string.
	 * @param s2 The second string.
	 * @return {@code true} if a common substring is found, {@code false} otherwise.
	 */
	static boolean hasCommonSubstringRolling(String s1, String s2) {
		if (s1.length() < RollState.ROLLING_WINDOW || s2.length() < RollState.ROLLING_WINDOW) {
			return false;
		}

		// Store hashes of all windows in s1.
		Set<Integer> hashes = new HashSet<>();
		RollState state1 = new RollState();
		for (int i = 0; i < s1.length(); i++) {
			state1.rollHash((byte) s1.charAt(i));
			if (i >= RollState.ROLLING_WINDOW - 1) {
				hashes.add(state1.rollSum());
			}
		}

		// Slide a window across s2, calculating hashes and checking for a match in the set.
		RollState state2 = new RollState();
		for (int i = 0; i < s2.length(); i++) {
			state2.rollHash((byte) s2.charAt(i));
			if (i >= RollState.ROLLING_WINDOW - 1) {
				if (hashes.contains(state2.rollSum())) {
					// On hash collision, verify with an actual string comparison.
					int s2_start = i - (RollState.ROLLING_WINDOW - 1);
					if (s1.contains(s2.substring(s2_start, s2_start + RollState.ROLLING_WINDOW))) {
						return true;
					}
				}
			}
		}
		return false;
	}

	/**
	 * Calculates the Levenshtein (edit) distance between two short strings (<= 64 chars)
	 * using the highly efficient Myers's bit-parallel algorithm.
	 *
	 * @param patternMask The pre-computed pattern bitmask for the first string.
	 * @param s1len       Length of the first string (pattern, shorter or equal length, length <= 64).
	 * @param s2          The second string (text, length <= 64).
	 * @return The edit distance between the two strings.
	 */
	static int editDistanceBitParallel(long[] patternMask, int s1len, String s2) {
		int s2len = s2.length();

		if (s1len == 0) {
			return s2len;
		}

		// Initialize DP state variables.
		int cur = s1len;
		long msb = 1L << (s1len - 1);
		long pv = -1L;
		long nv = 0;

		// Scan through the text (s2) and update DP state.
		for (int j = 0; j < s2len; j++) {
			long mt = patternMask[s2.charAt(j) - MIN_CHAR];

			long zd = (((mt & pv) + pv) ^ pv) | mt | nv;
			long nh = pv & zd;
			if ((nh & msb) != 0)
				--cur;
			long x = nv | ~(pv | zd) | (pv & ~mt & 1L);
			long y = (pv - nh) >>> 1;
			long ph = (x + y) ^ y;
			if ((ph & msb) != 0)
				++cur;
			x = (ph << 1) | 1L;
			nv = x & zd;
			pv = (nh << 1) | ~(x | zd) | (x & (pv - nh));
		}
		return cur;
	}

	/**
	 * A classic implementation of the Wagner-Fischer algorithm to compute a modified Levenshtein distance,
	 * used as a fallback for strings longer than 64 characters.
	 * <p>
	 * This implementation uses a substitution cost of 2, while insertion and deletion costs are 1.
	 *
	 * @param s1 The first string (shorter or equal length).
	 * @param s2 The second string (longer or equal length).
	 * @return The edit distance.
	 */
	static int editDistanceWagnerFischer(String s1, String s2) {
		int n = s1.length();
		int m = s2.length();
		int[] dp = new int[m + 1];

		for (int j = 0; j <= m; j++) {
			dp[j] = j;
		}

		for (int i = 1; i <= n; i++) {
			int prev = dp[0];
			dp[0] = i;
			for (int j = 1; j <= m; j++) {
				int temp = dp[j];
				if (s1.charAt(i - 1) == s2.charAt(j - 1)) {
					dp[j] = prev;
				} else {
					// Substitution cost is 2, insertion/deletion is 1.
					dp[j] = Math.min(prev + 2, Math.min(dp[j] + 1, dp[j - 1] + 1));
				}
				prev = temp;
			}
		}
		return dp[m];
	}

	private static int compareParsed(long blockSize1, String s1b1, String s1b2, long blockSize2, String s2b1, String s2b2) {

		// Check for an exact match.
		if (blockSize1 == blockSize2 && s1b1.equals(s2b1) && s1b2.equals(s2b2)) {
			return 100;
		}

		long score;
		if (blockSize1 == blockSize2) {
			int score1 = scoreStrings(s1b1, s2b1, blockSize1);
			int score2 = scoreStrings(s1b2, s2b2, blockSize1 * 2);
			score = Math.max(score1, score2);
		} else if (blockSize1 * 2 == blockSize2) {
			score = scoreStrings(s1b2, s2b1, blockSize2);
		} else { // blockSize1 / 2 == blockSize2
			score = scoreStrings(s1b1, s2b2, blockSize1);
		}

		return (int) score;
	}

}
