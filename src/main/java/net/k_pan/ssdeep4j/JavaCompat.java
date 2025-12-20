package net.k_pan.ssdeep4j;

public class JavaCompat {

	public static long parseLong(String s, int beginIndex, int endIndex) {
		return Long.parseLong(s.substring(beginIndex, endIndex));
	}
}
