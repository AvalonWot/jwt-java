package bestv.tv.xbox.sso.auth.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;
import java.util.zip.Inflater;

/**
 * Deflate (RFC 1951) utilities.
 * 
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-04-16)
 */
public class DeflateUtils {

	/**
	 * Omit headers and CRC fields from output, as specified by RFC 1950. Note
	 * that the Deflater JavaDocs are incorrect, see
	 * http://stackoverflow.com/questions
	 * /11076060/decompressing-gzipped-data-with-inflater-in-java
	 */
	private static final boolean NOWRAP = true;

	/**
	 * Compresses the specified byte array according to the DEFLATE
	 * specification (RFC 1951).
	 * 
	 * @param bytes
	 *            The byte array to compress. Must not be {@code null}.
	 * 
	 * @return The compressed bytes.
	 * 
	 * @throws IOException
	 *             If compression failed.
	 */
	public static byte[] compress(final byte[] bytes) throws IOException {

		ByteArrayOutputStream out = new ByteArrayOutputStream();

		DeflaterOutputStream def = new DeflaterOutputStream(out, new Deflater(
				Deflater.DEFLATED, NOWRAP));
		def.write(bytes);
		def.close();

		return out.toByteArray();
	}

	/**
	 * Decompresses the specified byte array according to the DEFLATE
	 * specification (RFC 1951).
	 * 
	 * @param bytes
	 *            The byte array to decompress. Must not be {@code null}.
	 * 
	 * @return The decompressed bytes.
	 * 
	 * @throws IOException
	 *             If decompression failed.
	 */
	public static String decompress(final byte[] bytes) throws IOException {

		InflaterInputStream inf = new InflaterInputStream(
				new ByteArrayInputStream(bytes), new Inflater(NOWRAP));
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		// Transfer bytes from the compressed array to the output
		byte[] buf = new byte[1024];

		int len;

		while ((len = inf.read(buf)) > 0) {

			out.write(buf, 0, len);
		}

		inf.close();
		out.close();
		return out.toString("UTF-8");//out.toByteArray();
	}

	public static String decompress1(final byte[] bytes) throws IOException {

		// InflaterInputStream inf = new InflaterInputStream(
		// new ByteArrayInputStream(bytes), new Inflater(NOWRAP));
		Inflater inf = new Inflater(true);
		// InputStream inf = new GZIPInputStream(new
		// ByteArrayInputStream(bytes));
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		// Transfer bytes from the compressed array to the output
		final byte[] buf = new byte[1024];
		int len;
		try {
			inf.setInput(bytes);
			while (!inf.finished() && (len = inf.inflate(buf)) > 0) {
				out.write(buf, 0, len);
			}
		} catch (DataFormatException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			inf.end();
		}
		// int len = -1;
		// while ((len = inf.read(buf, 0, bytes.length)) != -1) {
		// out.write(buf, 0, len);
		// }
		// inf.close();
		out.close();
		out.flush();
		return out.toString("UTF-8");
	}

	/**
	 * Prevents public instantiation.
	 */
	private DeflateUtils() {

	}
}