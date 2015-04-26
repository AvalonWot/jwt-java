package bestv.tv.xbox.sso.auth.utils;

import java.util.Collection;

public class Bytes {

	public static byte[] toArray(Collection<? extends Number> collection) {
		
		/*
		if (collection instanceof ByteArrayAsList) {
			return ((ByteArrayAsList) collection).toByteArray();
		}*/

		Object[] boxedArray = collection.toArray();
		int len = boxedArray.length;
		byte[] array = new byte[len];
		for (int i = 0; i < len; i++) {
			// checkNotNull for GWT (do not optimize)
			array[i] = ((Number) checkNotNull(boxedArray[i])).byteValue();
		}
		return array;
	}

	public static <T> T checkNotNull(T reference) {
		if (reference == null) {
			throw new NullPointerException();
		}
		return reference;
	}
 
}
