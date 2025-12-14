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

import java.util.Arrays;

/**
 * Manages the state of the rolling hash used within the ssdeep algorithm.
 * <p>
 * A rolling hash allows for the efficient calculation of hash values for a
 * sliding window of data. This implementation is a direct port of the logic
 * from the original C version of ssdeep and is a core component of the
 * {@link FuzzyComparator#hasCommonSubstring(String, String)} optimization.
 * <p>
 * This class is a package-private helper and is not intended for public use.
 */
final class RollState {
	/**
	 * The size of the rolling window, which also defines the length of the
	 * substring to be matched in the pre-check.
	 */
	public static final int ROLLING_WINDOW = 7;

	/**
	 * The circular buffer holding the current window of bytes.
	 */
	private final byte[] window = new byte[ROLLING_WINDOW];
	/**
	 * Parts of the rolling hash sum.
	 */
	private int h1, h2, h3;
	/**
	 * The current position within the circular buffer.
	 */
	private int n;

	/**
	 * Initializes or resets the state of the rolling hash to its default values.
	 */
	void rollInit() {
		Arrays.fill(window, (byte) 0);
		h1 = h2 = h3 = 0;
		n = 0;
	}

	/**
	 * Updates the rolling hash state with a new byte.
	 * The window slides, and the three hash components (h1, h2, h3) are recalculated.
	 *
	 * @param c The next byte from the input stream.
	 */
	void rollHash(byte c) {
		h2 -= h1;
		h2 += ROLLING_WINDOW * (c & 0xFF);

		h1 += (c & 0xFF);
		h1 -= (window[n] & 0xFF);

		window[n] = c;
		n = (n + 1) % ROLLING_WINDOW;

		h3 <<= 5;
		h3 ^= (c & 0xFF);
	}

	/**
	 * Computes and returns the current value of the rolling hash.
	 *
	 * @return The current rolling hash sum.
	 */
	int rollSum() {
		return h1 + h2 + h3;
	}
}
