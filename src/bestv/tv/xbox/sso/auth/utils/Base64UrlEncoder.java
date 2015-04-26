package bestv.tv.xbox.sso.auth.utils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;


import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;


public class Base64UrlEncoder {
	private static char Base64Character62 = '+';
    private static char Base64Character63 = '/';
    private static char Base64PadCharacter = '=';
    private static char Base64UrlCharacter62 = '-';
    private static char Base64UrlCharacter63 = '_';
    private static String DoubleBase64PadCharacter = "==";//String.format("%s%s", new Object[] {"="});

    public static String Decode(String arg) throws IOException
    {
    	try {
			return new String(DecodeBytes(arg), "UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "";
		}
    }

    public static byte[] DecodeBytes(String arg) throws IOException
    {
        if (StringUtil.isBlank(arg))
        {
            //throw new Exception("arg");
        	return null;
        }
        String s = arg;
        s = s.replace('-', '+').replace('_', '/');
        switch ((s.length() % 4))
        {
            case 0:
                break;
            case 2:
                s = s + DoubleBase64PadCharacter;
                break;
            case 3:
            	s = s + '=';
                break;
            default:
                //throw new DecodingException("Illegal base64url string!");
            	break;
        }
//        return Convert.FromBase64String(s);
        BASE64Decoder decoder = new BASE64Decoder();
        return decoder.decodeBuffer(s);
    }

    public static String Encode(String arg)
    {
        if (StringUtil.isBlank(arg))
        {
            //throw new Exception("arg to encode cannot be null or empty.");
        	return "";
        }
        return Encode(arg.getBytes());
    }

    public static String Encode(byte[] arg)
    {
        if (arg == null)
        {
//            throw new Exception("arg");
        	return "";
        }
//        String str = Convert.ToBase64String(arg).split(new char[] { '=' })[0];
        BASE64Encoder base64Encoder = new BASE64Encoder();
        String str = base64Encoder.encode(arg).split("=")[0];
        return str.replace('+', '-').replace('/', '_');
    }

}
