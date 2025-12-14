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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Generates ssdeep fuzzy hashes from various input sources.
 * <p>
 * This utility class provides static methods to compute fuzzy hashes for files,
 * byte arrays, and input streams. The implementation is a direct port of the
 * logic found in the original C version of ssdeep.
 * <p>
 * This class is non-instantiable and its methods are thread-safe.
 *
 * @see <a href="https://github.com/ssdeep-project/ssdeep/blob/master/fuzzy.c">ssdeep fuzzy.c</a>
 */
public final class FuzzyHasher {

	// Core parameters from the original ssdeep implementation.

	/**
	 * The maximum length of the ssdeep hash signatures.
	 */
	static final int SPAMSUM_LENGTH = 64;
	/**
	 * The maximum size of a fuzzy hash result string.
	 */
	static final int FUZZY_MAX_RESULT = 2 * SPAMSUM_LENGTH + 20;
	/**
	 * Flag to indicate that sequences of identical characters should be eliminated.
	 */
	static final int FUZZY_FLAG_ELIMSEQ = 1;
	/**
	 * Flag to prevent the second hash from being truncated.
	 */
	static final int FUZZY_FLAG_NOTRUNC = 2;

	/**
	 * The minimum block size used in the ssdeep algorithm.
	 */
	static final int MIN_BLOCKSIZE = 3;
	/**
	 * The initial value for the rolling hash.
	 */
	static final int HASH_INIT = 0x27;
	/**
	 * The number of block hash contexts to maintain for different block sizes.
	 */
	static final int NUM_BLOCKHASHES = 31;

	/**
	 * Non-instantiable utility class.
	 */
	private FuzzyHasher() {
	}

	/**
	 * Computes the fuzzy hash for the specified file.
	 *
	 * @param filePath The path to the file to be hashed.
	 * @return The computed fuzzy hash string.
	 * @throws IOException If an I/O error occurs reading from the file.
	 */
	public static String hash(Path filePath) throws IOException {
		try (InputStream in = Files.newInputStream(filePath)) {
			return hash(in);
		}
	}

	/**
	 * Computes the fuzzy hash for the specified byte array.
	 *
	 * @param content The byte array to be hashed.
	 * @return The computed fuzzy hash string.
	 * @throws IOException If an I/O error occurs during stream processing (unlikely).
	 */
	public static String hash(byte[] content) throws IOException {
		try (InputStream in = new ByteArrayInputStream(content)) {
			return hash(in);
		}
	}

	/**
	 * Computes the fuzzy hash from the given input stream.
	 * <p>
	 * This method processes the stream until it is exhausted. The stream is not
	 * closed by this method.
	 *
	 * @param inputStream The input stream to be hashed.
	 * @return The computed fuzzy hash string.
	 * @throws IOException If an I/O error occurs while reading from the stream.
	 */
	public static String hash(InputStream inputStream) throws IOException {
		FuzzyState state = new FuzzyState();
		state.engineUpdate(inputStream);
		return state.digest();
	}

	/**
	 * Truncates sequences of identical characters longer than three to a length of three.
	 * This is a requirement of the ssdeep algorithm.
	 * For example, "AAAAABBBCCCCCC" becomes "AAABBBCCC".
	 *
	 * @param input The string to process.
	 * @return The string with long sequences of identical characters eliminated.
	 */
	public static String copyEliminateSequences(String input) {
		if (input == null || input.length() < 4) {
			return input;
		}
		StringBuilder sb = new StringBuilder(input.length());
		sb.append(input, 0, 3);
		for (int i = 3; i < input.length(); i++) {
			char c = input.charAt(i);
			if (c != sb.charAt(sb.length() - 1) || c != sb.charAt(sb.length() - 2) || c != sb.charAt(sb.length() - 3)) {
				sb.append(c);
			}
		}
		return sb.toString();
	}

	/**
	 * Manages the overall state of the fuzzy hash computation.
	 * This class acts as the main engine for the hashing process.
	 * <p>
	 * While this class is public, most users should prefer the static {@code hash(...)}
	 * methods in {@link FuzzyHasher}. This class is intended for advanced use cases
	 * where data is not available all at once, such as processing a network stream.
	 * It allows for updating the hash state incrementally.
	 *
	 * <pre>{@code
	 * FuzzyState state = new FuzzyState();
	 * state.engineUpdate(chunk1);
	 * state.engineUpdate(chunk2);
	 * String hash = state.digest();
	 * }</pre>
	 */
	public static final class FuzzyState {
		private static final String B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		private static final byte[][] SUM_TABLE = SumTable.SUM_TABLE;

		private static long SSDEEP_BS(int index) { return (long) MIN_BLOCKSIZE << index; }
		private static final int FUZZY_STATE_NEED_LASTHASH = 1;
		private static final int FUZZY_STATE_SIZE_FIXED = 2;
		private static final long SSDEEP_TOTAL_SIZE_MAX = SSDEEP_BS(NUM_BLOCKHASHES - 1) * SPAMSUM_LENGTH;

		private final RollState roll = new RollState();
		private final BlockhashContext[] bh = new BlockhashContext[NUM_BLOCKHASHES];
		private long totalSize = 0;
		private long fixedSize = 0;
		private long reduceBorder = (long) MIN_BLOCKSIZE * SPAMSUM_LENGTH;
		private int bhStart = 0;
		private int bhEnd = 1;
		private int bhEndLimit = NUM_BLOCKHASHES - 1;
		private int flags = 0;
		private byte lastH;
		private int rollmask = 0;

		/**
		 * Initializes a new fuzzy hashing session.
		 */
		public FuzzyState() {
			for (int i = 0; i < NUM_BLOCKHASHES; i++) {
				bh[i] = new BlockhashContext();
			}
			roll.rollInit();
		}

		/**
		 * Updates the hash state with data from an input stream.
		 * This method can be called multiple times to process data in chunks.
		 * The stream is read until exhausted but is not closed by this method.
		 *
		 * @param in The input stream containing the data to be hashed.
		 * @throws IOException If an I/O error occurs while reading from the stream.
		 */
		public void engineUpdate(InputStream in) throws IOException {
			byte[] buffer = new byte[8192];
			int bytesRead;

			while ((bytesRead = in.read(buffer)) != -1) {
				for (int i = 0; i < bytesRead; i++) {
					engineStep(buffer[i]);
				}
			}
		}

		/**
		 * Computes and returns the final fuzzy hash string from the data processed so far.
		 * After this method is called, the {@code FuzzyState} instance should generally
		 * not be reused for further updates.
		 *
		 * @return The computed ssdeep fuzzy hash string, or an empty string if an error occurred.
		 */
		public String digest() {

			int bi = bhStart;
			int h = roll.rollSum();
			StringBuilder result = new StringBuilder(FUZZY_MAX_RESULT);

			if (totalSize > SSDEEP_TOTAL_SIZE_MAX) {
				/* The input exceeds data types. */
				return "";
			}
			/* Fixed size optimization. */
			if ((flags & FUZZY_STATE_SIZE_FIXED) != 0 && fixedSize != totalSize) {
				return "";
			}
			/* Initial blocksize guess. */
			while (SSDEEP_BS(bi) * SPAMSUM_LENGTH < totalSize)
				++bi;
			/* Adapt blocksize guess to actual digest length. */
			if (bi >= bhEnd)
				bi = bhEnd - 1;
			while (bi > bhStart && bh[bi].getFirstDigestLength() < SPAMSUM_LENGTH / 2) {
				--bi;
			}

			result.append(SSDEEP_BS(bi));
			result.append(':');
			if ((flags & FUZZY_FLAG_ELIMSEQ) != 0)
				result.append(copyEliminateSequences(bh[bi].getFirstDigest()));
			else
				result.append(bh[bi].getFirstDigest());
			if (h != 0) {
				char r = B64.charAt(bh[bi].h & 0xFF);
				if (canAppend(r, result)) {
					result.append(r);
				}
			} else {
				char r = bh[bi].getLastDigest();
				if (r != '\0') {
					if (canAppend(r, result)) {
						result.append(r);
					}
				}
			}
			result.append(':');
			if (bi < bhEnd - 1) {
				++bi;
				if ((flags & FUZZY_FLAG_NOTRUNC) == 0) {
					bh[bi].trimDigestLength(SPAMSUM_LENGTH / 2 - 1);
				}

				if ((flags & FUZZY_FLAG_ELIMSEQ) != 0)
					result.append(copyEliminateSequences(bh[bi].getFirstDigest()));
				else
					result.append(bh[bi].getFirstDigest());

				if (h != 0) {
					int hashVal = (flags & FUZZY_FLAG_NOTRUNC) != 0
							? bh[bi].h
							: bh[bi].half_h;
					char r = B64.charAt(hashVal & 0xFF);
					if (canAppend(r, result)) {
						result.append(r);
					}
				} else {
					char r = (flags & FUZZY_FLAG_NOTRUNC) != 0
							? bh[bi].getLastDigest()
							: bh[bi].half_digest;
					if (r != '\0') {
						if (canAppend(r, result)) {
							result.append(r);
						}
					}
				}
			} else if (h != 0) {
				assert (bi == 0 || bi == NUM_BLOCKHASHES - 1);
				if (bi == 0)
					result.append(B64.charAt(bh[bi].h & 0xFF));
				else
					result.append(B64.charAt(lastH & 0xFF));
				/* No need to bother with FUZZY_FLAG_ELIMSEQ, because this
				 * digest has length 1. */
			}
			return result.toString();
		}

		/**
		 * Optimizes hashing by setting the total expected input size in advance.
		 * This is an optional call. If the total size of the input data is known
		 * beforehand, calling this method can improve the selection of the initial
		 * block size.
		 *
		 * @param totalFixedLength The total expected size of the input data in bytes.
		 * @return 0 on success, -1 on failure (e.g., if the size is too large or
		 *         conflicts with a previously set size).
		 */
		public int setTotalInputLength(long totalFixedLength) {
			int bi = 0;
			if (totalFixedLength > SSDEEP_TOTAL_SIZE_MAX) {
				return -1;
			}
			if ((flags & FUZZY_STATE_SIZE_FIXED) != 0 && fixedSize != totalFixedLength) {
				return -1;
			}
			flags |= FUZZY_STATE_SIZE_FIXED;
			fixedSize = totalFixedLength;
			while (SSDEEP_BS(bi) * SPAMSUM_LENGTH < totalFixedLength) {
				++bi;
				if (bi == NUM_BLOCKHASHES - 2)
					break;
			}
			++bi;
			bhEndLimit = bi;
			return 0;
		}

		private void engineStep(byte c) {
			totalSize++;
			/* At each character we update the rolling hash and the normal hashes.
			 * When the rolling hash hits a reset value then we emit a normal hash
			 * as a element of the signature and reset the normal hash. */
			roll.rollHash(c);
			int horg = roll.rollSum() + 1;
			int h = (int) (Integer.toUnsignedLong(horg) / MIN_BLOCKSIZE);

			for (int i = bhStart; i < bhEnd; i++) {
				bh[i].h = sumHash(c, bh[i].h);
				bh[i].half_h = sumHash(c, bh[i].half_h);
			}
			if ((flags & FUZZY_STATE_NEED_LASTHASH) != 0) {
				lastH = sumHash(c, lastH);
			}

			/* 0xffffffff !== -1 (mod 3) */
			if (horg == 0) {
				return;
			}

			/* With growing blocksize almost no runs fail the next test. */
			if ((h & rollmask) != 0) {
				return;
			}

			/* Delay computation of modulo as possible. */
			if (Integer.toUnsignedLong(horg) % MIN_BLOCKSIZE != 0) {
				return;
			}

			h >>>= bhStart;

			int i = bhStart;
			do {
				/* We have hit a reset point. We now emit hashes which are
				 * based on all characters in the piece of the message between
				 * the last reset point and this one */
				if (bh[i].getFirstDigestLength() == 0) {
					/* Can only happen 30 times. */
					/* First step for this blocksize. Clone next. */
					tryForkBlockHash();
				}

				bh[i].half_digest = B64.charAt(bh[i].half_h & 0xFF);
				if (bh[i].pushDigest(B64.charAt(bh[i].h & 0xFF))) {
					/* We can have a problem with the tail overflowing. The
					 * easiest way to cope with this is to only reset the
					 * normal hash if we have room for more characters in
					 * our signature. This has the effect of combining the
					 * last few pieces of the message into a single piece
					 * */
					bh[i].h = HASH_INIT;
					if (bh[i].getFirstDigestLength() < SPAMSUM_LENGTH / 2) {
						bh[i].half_h = HASH_INIT;
						bh[i].half_digest = '\0';
					}
				} else {
					tryReduceBlockHash();
				}

				if ((h & 1) != 0) {
					break;
				}
				h >>>= 1;
			}
			while (++i < bhEnd);
		}

		private void tryForkBlockHash() {
			BlockhashContext obh = bh[bhEnd - 1];
			if (bhEnd <= bhEndLimit) {
				BlockhashContext nbh = bh[bhEnd];
				nbh.h = obh.h;
				nbh.half_h = obh.half_h;
				nbh.clearDigest();
				nbh.half_digest = '\0';
				bhEnd++;
			} else if (bhEnd == NUM_BLOCKHASHES && (flags & FUZZY_STATE_NEED_LASTHASH) == 0) {
				flags |= FUZZY_STATE_NEED_LASTHASH;
				lastH = obh.h;
			}
		}

		private void tryReduceBlockHash() {
			if (bhEnd - bhStart < 2) {
				/* Need at least two working hashes. */
				return;
			}
			if (reduceBorder >= ((flags & FUZZY_STATE_SIZE_FIXED) != 0 ? fixedSize : totalSize)) {
				/* Initial blocksize estimate would select this or a smaller blocksize. */
				return;
			}
			if (bh[bhStart + 1].getFirstDigestLength() < SPAMSUM_LENGTH / 2) {
				/* Estimate adjustment would select this blocksize. */
				return;
			}
			/* At this point we are clearly no longer interested in the start_blocksize. Get rid of it. */
			bhStart++;
			reduceBorder *= 2;
			rollmask = (rollmask << 1) | 1;
		}

		private boolean canAppend(char c, StringBuilder sb) {
			if ((flags & FUZZY_FLAG_ELIMSEQ) == 0) {
				return true;
			}
			int len = sb.length();
			return len < 3 || c != sb.charAt(len - 1) || c != sb.charAt(len - 2) || c != sb.charAt(len - 3);
		}

		private static byte sumHash(byte c, byte h) {
			return SUM_TABLE[h & 0xFF][c & 0x3F];
		}

		/**
		 * Manages the hash state for a specific block size.
		 */
		private static final class BlockhashContext {
			private final char[] digest = new char[SPAMSUM_LENGTH - 1];
			private int dindex = 0;
			private char lastDigest = '\0';
			private char half_digest = '\0';
			private byte h = HASH_INIT;
			private byte half_h = HASH_INIT;

			public void clearDigest() {
				dindex = 0;
				lastDigest = '\0';
			}

			public int getFirstDigestLength() {
				return dindex;
			}

			public String getFirstDigest() {
				return new String(digest, 0, dindex);
			}

			public char getLastDigest() {
				return lastDigest;
			}

			public boolean pushDigest(char c) {

				if (dindex < digest.length) {
					/* We can have a problem with the tail overflowing. The
					 * easiest way to cope with this is to only reset the
					 * normal hash if we have room for more characters in
					 * our signature. This has the effect of combining the
					 * last few pieces of the message into a single piece
					 * */
					digest[dindex] = c;
					dindex++;
					return true;
				} else {
					lastDigest = c;
					return false;
				}
			}

			public void trimDigestLength(int maxLength) {
				if (dindex > maxLength) {
					dindex = maxLength;
					lastDigest = '\0';
				}
			}
		}

	}

}
