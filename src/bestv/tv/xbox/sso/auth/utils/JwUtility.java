package bestv.tv.xbox.sso.auth.utils;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

//import com.google.common.primitives.Bytes;

public class JwUtility {

	public static boolean ArrayCompare(byte[] arr1, byte[] arr2) {
		if ((arr1 == null) || (arr2 == null)) {
			return (arr2 == arr1);
		}
		if (arr1.length != arr2.length) {
			return false;
		}
		for (int i = 0; i < arr1.length; i++) {
			if (arr1[i] != arr2[i]) {
				return false;
			}
		}
		return true;
	}

	public static byte[] ArrayConcat(byte[][] args) {
		if (args == null) {
			return new byte[0];
		}
		int num = 0;
		for (byte[] buffer : args) {
			if (buffer != null) {
				num += buffer.length;
			}
		}
		byte[] dst = new byte[num];
		int dstOffset = 0;
		for (byte[] buffer3 : args) {
			if (buffer3 != null) {
				// Buffer.BlockCopy(buffer3, 0, dst, dstOffset, buffer3.length);
				System.arraycopy(buffer3, 0, dst, dstOffset, buffer3.length);
				dstOffset += buffer3.length;
			}
		}
		return dst;
	}

	public static byte[] ConcatKdf(byte[] cmk, String enc, String add,  //"A128CBC+HS256", Encryption, 128
			int keydatalen) throws UnsupportedEncodingException,
			NoSuchAlgorithmException, Exception {
		int count = keydatalen / 8;  // = 16
		byte[] bytes = enc.getBytes("UTF-8");
		byte[] buffer2 = add.getBytes("ASCII");
		// byte[] bytes = Encoding.UTF8.GetBytes(enc);
		// byte[] buffer2 = Encoding.ASCII.GetBytes(label);
		List<Byte> source = new ArrayList<Byte>();

		for (int i = 1; source.size() < count; i++) {
			byte[] buffer = ArrayConcat(new byte[][] { ConvertToBigEndian(i),
					cmk, ConvertToBigEndian(keydatalen), bytes,
					ConvertToBigEndian(0), ConvertToBigEndian(0), buffer2 });
			// source.addLast()
			// Check MAC
			// int hmacInputLength = aad.length + iv.length + cipherText.length
			// + al.length;
			// byte[] hmacInput =
			// ByteBuffer.allocate(hmacInputLength).put(aad).put(iv).put(cipherText).put(al).array();
			Security.addProvider(new BouncyCastleProvider());
			MessageDigest md;
			md = MessageDigest.getInstance("SHA256");
			// byte[] hmac = new byte[32];
			md.update(buffer, 0, buffer.length);

			for (byte b : md.digest()) {
				source.add(b);
			}
			// HMAC
			// source.AddRange(sha.ComputeHash(buffer));
		}
		return Bytes.toArray(source.subList(0, count));
	}

	private static byte[] ConvertToBigEndian(int i) {
		// TODO Auto-generated method stub
		return BitConverter.GetBytes(i);
	}

	public static String convertToHex(byte[] data) {
		if (data == null)
			return null;
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < data.length; i++) {
			int halfbyte = (data[i] >>> 4) & 0x0F;
			int two_halfs = 0;
			do {
				if ((0 <= halfbyte) && (halfbyte <= 9))
					buf.append((char) ('0' + halfbyte));
				else
					buf.append((char) ('a' + (halfbyte - 10)));
				halfbyte = data[i] & 0x0F;
			} while (two_halfs++ < 1);
		}
		return buf.toString();
	}

	/**
	 * 将二进制转换成16进制
	 * 
	 * @param buf
	 * @return
	 */
	public static String parseByte2HexStr(byte buf[]) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < buf.length; i++) {
			String hex = Integer.toHexString(buf[i] & 0xFF);
			if (hex.length() == 1) {
				hex = '0' + hex;
			}
			sb.append(hex.toUpperCase());
		}
		return sb.toString();
	}

	/**
	 * 将16进制转换为二进制
	 * 
	 * @param hexStr
	 * @return
	 */
	public static byte[] parseHexStr2Byte(String hexStr) {
		if (hexStr.length() < 1)
			return null;
		byte[] result = new byte[hexStr.length() / 2];
		for (int i = 0; i < hexStr.length() / 2; i++) {
			int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
			int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2),
					16);
			result[i] = (byte) (high * 16 + low);
		}
		return result;
	}

	public static String hexify(byte bytes[]) {

		char[] hexDigits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
				'a', 'b', 'c', 'd', 'e', 'f' };

		StringBuffer buf = new StringBuffer(bytes.length * 2);

		for (int i = 0; i < bytes.length; ++i) {
			buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
			buf.append(hexDigits[bytes[i] & 0x0f]);
		}

		return buf.toString();
	}

}
