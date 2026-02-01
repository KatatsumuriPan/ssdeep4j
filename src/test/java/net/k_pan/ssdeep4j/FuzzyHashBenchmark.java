package net.k_pan.ssdeep4j;

import java.io.IOException;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Fork(1)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
public class FuzzyHashBenchmark {

	// Test with various data sizes to produce hashes of different lengths.
	// 50: Very short hash
	// 500: Medium length hash
	// 5000: Long hash (near max length)
	// 50000: Long hash with larger block size
	@Param({"50", "500", "5000", "50000"})
	private int dataSize;

	private String targetHashStr;
	private String[] otherHashesStr;
	private FuzzyHash targetHash;
	private FuzzyHash[] otherHashes;

	@Setup
	public void setup() throws IOException {
		Random random = new Random(12345); // Fixed seed for reproducibility

		// 1. Generate Target Data and Hash
		byte[] targetData = new byte[dataSize];
		random.nextBytes(targetData);
		targetHashStr = FuzzyHasher.hash(targetData);
		targetHash = new FuzzyHash(targetHashStr);

		// 2. Generate Other Hashes (Match, Near-Match, No-Match)
		otherHashesStr = new String[5];

		// Case 0: Exact Match
		otherHashesStr[0] = targetHashStr;

		// Case 1: Near Match (Change 1 byte)
		byte[] nearData1 = targetData.clone();
		nearData1[dataSize / 2] ^= 0xFF;
		otherHashesStr[1] = FuzzyHasher.hash(nearData1);

		// Case 2: Near Match (Change 5% of bytes)
		byte[] nearData2 = targetData.clone();
		for (int i = 0; i < dataSize / 20; i++) {
			nearData2[random.nextInt(dataSize)] ^= 0xFF;
		}
		otherHashesStr[2] = FuzzyHasher.hash(nearData2);

		// Case 3: No Match (Random data of same size)
		byte[] noMatchData = new byte[dataSize];
		random.nextBytes(noMatchData);
		otherHashesStr[3] = FuzzyHasher.hash(noMatchData);

		// Case 4: Different Size (Random data of half size)
		byte[] diffSizeData = new byte[dataSize / 2 + 1]; // +1 to avoid 0 if dataSize is small
		random.nextBytes(diffSizeData);
		otherHashesStr[4] = FuzzyHasher.hash(diffSizeData);

		// 3. Create FuzzyHash objects for benchmarks that use them
		otherHashes = new FuzzyHash[otherHashesStr.length];
		for (int i = 0; i < otherHashesStr.length; i++) {
			try {
				otherHashes[i] = new FuzzyHash(otherHashesStr[i]);
			} catch (IllegalArgumentException e) {
				// Handle cases where a generated hash might be invalid (e.g., from very small data)
				otherHashes[i] = null;
			}
		}
	}

	@Benchmark
	public int testStaticComparator_String() {
		int totalScore = 0;
		for (String other : otherHashesStr) {
			totalScore += FuzzyComparator.compare(targetHashStr, other);
		}
		return totalScore;
	}

	@Benchmark
	public int testFuzzyHash_compareToString() {
		int totalScore = 0;
		for (String other : otherHashesStr) {
			totalScore += targetHash.compare(other);
		}
		return totalScore;
	}

	@Benchmark
	public int testFuzzyHash_compareToFuzzyHash() {
		int totalScore = 0;
		for (FuzzyHash other : otherHashes) {
			totalScore += targetHash.compare(other);
		}
		return totalScore;
	}

	@Benchmark
	public int testStaticComparator_FuzzyHash() {
		int totalScore = 0;
		for (FuzzyHash other : otherHashes) {
			totalScore += FuzzyComparator.compare(targetHash, other);
		}
		return totalScore;
	}

	@Benchmark
	public int testParseOnly() {
		int dummy = 0;
		for (String other : otherHashesStr) {
			try {
				FuzzyHash h = new FuzzyHash(other);
				dummy += h.getBlockSize();
			} catch (IllegalArgumentException e) {
				// ignore
			}
		}
		return dummy;
	}

	public static void main(String[] args) throws RunnerException {
		Options opt = new OptionsBuilder().include(FuzzyHashBenchmark.class.getSimpleName()).forks(1).build();

		new Runner(opt).run();
	}
}
