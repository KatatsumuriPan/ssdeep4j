package net.k_pan.ssdeep4j;

@SuppressWarnings("unused")
public class JavaCompat {

	public static long parseLong(String s, int beginIndex, int endIndex) {
		return Long.parseLong(s, beginIndex, endIndex, 10);
	}
}
