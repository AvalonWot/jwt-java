package bestv.tv.xbox.sso.auth;

import bestv.tv.xbox.sso.auth.exception.XboxSSOAuthException;
import bestv.tv.xbox.sso.auth.model.XDI;
import bestv.tv.xbox.sso.auth.model.XSTSToken;
import bestv.tv.xbox.sso.auth.model.XTI;
import bestv.tv.xbox.sso.auth.model.XUI;
import bestv.tv.xbox.sso.auth.utils.*;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.encoders.Base64;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;


public class JWT {

	private static final Logger logger = Logger.getLogger(JWT.class);

	private final static String BestvSSOPrivateKeyFile = "xsts.auth.bestv.com.pkcs8_der.key";
	private final static String BestvSSOCertificateFile = "xsts.auth.bestv.com.cer";
	private final static String XboxSSOCertificateFile = "xsts.auth.xboxlive.com.cer";

	private static Key bestvSSOPrivateKey;
	private static Key bestvSSOPublicKey;
	private static Certificate bestvSSOCertificate;
	private static Certificate xboxSSOCertificate;
	private static Key xboxSSOPublicKey;

	private static String USERHASH = "";
	private static JWT instance = new JWT();

	private JWT() {
		try {
			InitConfig();
		} catch (XboxSSOAuthException e) {
			// TODO Auto-generated catch block
			try {
				throw new XboxSSOAuthException(e.getErrorCode(), e.getMessage());
			} catch (XboxSSOAuthException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
	}

	public static JWT me() {
		return instance;
	}

	public String parseJWTString(String authorization)
			throws XboxSSOAuthException {
		return parseJWTString(authorization, true);
	}

	public String parseOOBEJWTString(String authorization,
			boolean verifyTokenExp) throws XboxSSOAuthException {
		logger.info("authorization:" + authorization);
		if (StringUtil.isBlank(authorization)) {
			logger.error("参数authorization为空！");
			throw new XboxSSOAuthException(-1101, "参数值为空或者不符合规范！");
		}

		String encryptedToken = authorization;
		logger.info("encryptedToken:" + encryptedToken);
		String[] arrEncryptedToken = encryptedToken.split("\\.");
		if (arrEncryptedToken.length != 5) {
			logger.error("无效的XBOX TOKEN加密信息，Token必须有5个段！");
			throw new XboxSSOAuthException(-1101, "参数值为空或者不符合规范!");
		}
		String jwtHeader = arrEncryptedToken[0];
		JSONObject jwtHeaderObject;
		try {
			jwtHeaderObject = (JSONObject) JSONValue
					.parseWithException(Base64UrlEncoder.Decode(jwtHeader));
			logger.info("jwtHeader:" + Base64UrlEncoder.Decode(jwtHeader));
		} catch (org.json.simple.parser.ParseException e) {
			// TODO Auto-generated catch block
			logger.error("解析JWTHeader JSON格式失败，" + e.getMessage());
			throw new XboxSSOAuthException(-1104, "XBOXTOKEN认证头信息不可用!");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			logger.error("解析JWTHeader失败，" + e.getMessage());
			throw new XboxSSOAuthException(-1104, "XBOXTOKEN认证头信息不可用!");
		}

		byte[] encryptedCmk = null;
		byte[] cipherText = null;
		byte[] iv = null;
		byte[] thumbprint = null;
		byte[] expectedIntegrityValue = null;
		
		boolean flag = jwtHeaderObject.containsKey("zip");
		String str3 = null;
		if (jwtHeaderObject.containsKey("x5t")) {
			str3 = (String) jwtHeaderObject.get("x5t");
		}

		try {
			if (!StringUtil.isBlank(str3)) {

				thumbprint = Base64UrlEncoder.DecodeBytes(str3);
			}

			String str4 = arrEncryptedToken[1];
			if (!StringUtil.isBlank(str4)) {
				encryptedCmk = Base64UrlEncoder.DecodeBytes(str4);
			}
			String str5 = arrEncryptedToken[2];
			if (!StringUtil.isBlank(str5)) {
				iv = Base64UrlEncoder.DecodeBytes(str5);
			}
			String str6 = arrEncryptedToken[3];
			if (!StringUtil.isBlank(str6)) {
				cipherText = Base64UrlEncoder.DecodeBytes(str6.trim());
			}
			String str7 = arrEncryptedToken[4];
			if (!StringUtil.isBlank(str7)) {
				expectedIntegrityValue = Base64UrlEncoder.DecodeBytes(str7);
			}
		} catch (IOException e) {
			logger.error("解析JWTHeader失败，" + e.getMessage());
			throw new XboxSSOAuthException(-1104, "XBOXTOKEN认证头信息不可用!");
		}

		if (thumbprint != null) {
			//System.out.println(JwUtility.hexify(thumbprint));
			RSAEngine engine = new RSAEngine();
			OAEPEncoding cipher = new OAEPEncoding(engine);
			// PKCS1Encoding cipher = new PKCS1Encoding(engine);
			BigInteger mod = ((RSAKey) bestvSSOPrivateKey).getModulus();
			BigInteger exp = ((RSAPrivateKey) bestvSSOPrivateKey)
					.getPrivateExponent();

			RSAKeyParameters keyParams = new RSAKeyParameters(true, mod, exp);
			cipher.init(false, keyParams);
			byte[] cmk = null;
			byte[] aesKey = null;
			byte[] plainText = null;
			String plainTextString = null;
			try {

				cmk = cipher.processBlock(encryptedCmk, 0, encryptedCmk.length);
				aesKey = JwUtility.ConcatKdf(cmk, "A128CBC+HS256",
						"Encryption", 128);
				plainText = decrypted(aesKey, iv, cipherText);
				if(flag){
					plainTextString = DeflateUtils.decompress1(plainText);
				}
				else {
					plainTextString = new String(plainText, "UTF-8");
				}
			} catch (Exception e) {
				logger.error("1105,JWT解密失败! =======>>>" + e.getMessage());
				throw new XboxSSOAuthException(-1105, "XBOXTOKEN内部错误!");
			}

			String token = plainTextString;// new
											// String(Base64.decodeBase64(plainTextString));
			logger.info("token:" + token);

			// JSONObject tokenObject = (JSONObject) JSONValue.parse(token);
			// String tokenExp = tokenObject.get("exp").toString();
			// logger.info("currentTimes:" + System.currentTimeMillis());
			// logger.info("tokenExp:"
			// + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(Long
			// .parseLong(tokenExp) * 1000));
			//
			// if (verifyTokenExp == true
			// && Long.parseLong(tokenExp) * 1000 < System
			// .currentTimeMillis())
			// throw new XboxSSOAuthException(-1106, "XBOXToken已过期！");
			return token;
		} else {
			throw new XboxSSOAuthException(-1107, "XBOXToken证书签名无效！");
		}
	}

	public String parseJWTString(String authorization, boolean verifyTokenExp)
			throws XboxSSOAuthException {
		logger.info("authorization:" + authorization);
		if (StringUtil.isBlank(authorization)) {
			logger.error("参数authorization为空！");
			throw new XboxSSOAuthException(-1101, "参数值为空或者不符合规范！");
		}
		if (!authorization.contains("XBL")) {
			logger.error("authorization信息中未包含XBL！authorization:"
					+ authorization);
			throw new XboxSSOAuthException(-1101, "参数值为空或者不符合规范!");
		}
		String[] arrAuthorization = null;
		try {
			arrAuthorization = authorization.split(";");
		} catch (Exception e) {
			logger.error("xbox userHash and token拆分失败！");
			throw new XboxSSOAuthException(-1101, "参数值为空或者不符合规范!");
		}
		USERHASH = arrAuthorization[0].split("=")[1];
		logger.info("userHash:" + USERHASH);
		String encryptedToken = arrAuthorization[1];
		logger.info("encryptedToken:" + encryptedToken);
		String[] arrEncryptedToken = encryptedToken.split("\\.");
		if (arrEncryptedToken.length != 5) {
			logger.error("无效的XBOX TOKEN加密信息，Token必须有5个段！");
			throw new XboxSSOAuthException(-1101, "参数值为空或者不符合规范!");
		}
		String jwtHeader = arrEncryptedToken[0];
		JSONObject jwtHeaderObject;
		try {
			jwtHeaderObject = (JSONObject) JSONValue
					.parseWithException(Base64UrlEncoder.Decode(jwtHeader));
			logger.info("jwtHeader:" + Base64UrlEncoder.Decode(jwtHeader));
		} catch (org.json.simple.parser.ParseException e) {
			// TODO Auto-generated catch block
			logger.error("解析JWTHeader JSON格式失败，" + e.getMessage());
			throw new XboxSSOAuthException(-1104, "XBOXTOKEN认证头信息不可用!");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			logger.error("解析JWTHeader失败，" + e.getMessage());
			throw new XboxSSOAuthException(-1104, "XBOXTOKEN认证头信息不可用!");
		}

		byte[] encryptedCmk = null;
		byte[] cipherText = null;
		byte[] iv = null;
		byte[] thumbprint = null;
		byte[] expectedIntegrityValue = null;

		boolean flag = jwtHeaderObject.containsKey("zip");
		String str3 = null;
		if (jwtHeaderObject.containsKey("x5t")) {
			str3 = (String) jwtHeaderObject.get("x5t");
		}

		try {
			if (!StringUtil.isBlank(str3)) {

				thumbprint = Base64UrlEncoder.DecodeBytes(str3);
				//System.out.println(JwUtility.hexify(thumbprint));
			}

			String str4 = arrEncryptedToken[1];
			if (!StringUtil.isBlank(str4)) {
				encryptedCmk = Base64UrlEncoder.DecodeBytes(str4);
			}
			String str5 = arrEncryptedToken[2];
			if (!StringUtil.isBlank(str5)) {
				iv = Base64UrlEncoder.DecodeBytes(str5);
			}
			String str6 = arrEncryptedToken[3];
			if (!StringUtil.isBlank(str6)) {
				cipherText = Base64UrlEncoder.DecodeBytes(str6.trim());
			}
			String str7 = arrEncryptedToken[4];
			if (!StringUtil.isBlank(str7)) {
				expectedIntegrityValue = Base64UrlEncoder.DecodeBytes(str7);
			}
		} catch (IOException e) {
			logger.error("解析JWTHeader失败，" + e.getMessage());
			throw new XboxSSOAuthException(-1104, "XBOXTOKEN认证头信息不可用!");
		}

		if (thumbprint != null) {

			RSAEngine engine = new RSAEngine();
			OAEPEncoding cipher = new OAEPEncoding(engine);

			BigInteger mod = ((RSAKey) bestvSSOPrivateKey).getModulus();
			BigInteger exp = ((RSAPrivateKey) bestvSSOPrivateKey)
					.getPrivateExponent();

			RSAKeyParameters keyParams = new RSAKeyParameters(true, mod, exp);
			cipher.init(false, keyParams);
			byte[] cmk = null;
			byte[] aesKey = null;
			byte[] plainText = null;
			String plainTextString = null;
			try {
				cmk = cipher.processBlock(encryptedCmk, 0, encryptedCmk.length);
				aesKey = JwUtility.ConcatKdf(cmk, "A128CBC+HS256",
						"Encryption", 128);
				plainText = decrypted(aesKey, iv, cipherText);
				if(flag)
					plainTextString = DeflateUtils.decompress1(plainText);
				else
					plainTextString = new String(plainText, "UTF-8");
			} catch (Exception e) {
				logger.error("1105,JWT解密失败! =======>>>" + e.getMessage());
				throw new XboxSSOAuthException(-1105, "XBOXTOKEN内部错误!");
			}

			String token = new String(Base64.decode(plainTextString
                    .split("\\.")[1]));
			logger.info("token:" + token);

			JSONObject tokenObject = (JSONObject) JSONValue.parse(token);
			String tokenExp = tokenObject.get("exp").toString();
			logger.info("currentTimes:" + System.currentTimeMillis());
			logger.info("tokenExp:"
					+ new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(Long
							.parseLong(tokenExp) * 1000));

			if (verifyTokenExp == true
					&& Long.parseLong(tokenExp) * 1000 < System
							.currentTimeMillis())
				throw new XboxSSOAuthException(-1106, "XBOXToken已过期！");
			return token;
		} else {
			throw new XboxSSOAuthException(-1107, "XBOXToken证书签名无效！");
		}
	}

	/**
	 * 解密XSTSToken，验证token有效期
	 * 
	 * @param authorization
	 * @return
	 * @throws Exception
	 */
	public XSTSToken parseJWEString(String authorization) throws Exception {
		return parseJWEString(authorization, true);
	}

	/**
	 * 解密XSTSToken
	 * 
	 * @param authorization
	 * @param verifyTokenExp
	 * @return
	 * @throws Exception
	 */
	public XSTSToken parseJWEString(String authorization, boolean verifyTokenExp)
			throws XboxSSOAuthException {

		String token = parseJWTString(authorization, verifyTokenExp);
		XSTSToken xstsToken = new XSTSToken();
		JSONObject tokenObject = (JSONObject) JSONValue.parse(token);
		if (tokenObject.containsKey("aud"))
			xstsToken.setAudience(tokenObject.get("aud").toString());
		if (tokenObject.containsKey("iss"))
			xstsToken.setIssuer(tokenObject.get("iss").toString());
		if (tokenObject.containsKey("sbx"))
			xstsToken.setSandboxID(tokenObject.get("sbx").toString());
		String tokenExp = "";
		if (tokenObject.containsKey("exp"))
			tokenExp = tokenObject.get("exp").toString();
		xstsToken.setTokenExpiration(tokenExp);
		if (tokenObject.containsKey("nbf"))
			xstsToken.setTokenIssueDate(tokenObject.get("nbf").toString());

		if (tokenObject.containsKey("xdi")) {
			JSONObject xdi = (JSONObject) tokenObject.get("xdi");
			XDI xdiEntity = new XDI();
			if (xdi.containsKey("ddm"))
				xdiEntity.setDeviceDebug(xdi.get("ddm").toString());
			if (xdi.containsKey("dty"))
				xdiEntity.setDeviceType(xdi.get("dty").toString());
			if (xdi.containsKey("dvr"))
				xdiEntity.setDeviceVersion(xdi.get("dvr").toString());
			if (xdi.containsKey("dpi"))
				xdiEntity.setDevicePairwiseID(xdi.get("dpi").toString());
			xstsToken.setXdi(xdiEntity);
		}
		if (tokenObject.containsKey("xti")) {
			JSONObject xti = (JSONObject) tokenObject.get("xti");
			XTI xtiEntity = new XTI();
			if (xti.containsKey("tid"))
				xtiEntity.setTitleID(xti.get("tid").toString());
			if (xti.containsKey("tvr"))
				xtiEntity.setTitleVersion(xti.get("tvr").toString());
			xstsToken.setXti(xtiEntity);
		}
		if (tokenObject.containsKey("xui")) {
			JSONArray xui = (JSONArray) tokenObject.get("xui");
			List<XUI> list = new ArrayList<XUI>();
			for (Object object : xui) {
				JSONObject tmpJsonObject = (JSONObject) object;
				XUI xuiEntity = new XUI();
				if (tmpJsonObject.containsKey("gtg"))
					xuiEntity.setGamertag(tmpJsonObject.get("gtg").toString());
				if (tmpJsonObject.containsKey("uts"))
					xuiEntity.setTest(tmpJsonObject.get("uts").toString());
				if (tmpJsonObject.containsKey("uhs"))
					xuiEntity.setUserHash(tmpJsonObject.get("uhs").toString());
				if (tmpJsonObject.containsKey("upi"))
					xuiEntity.setUserPairwiseID(tmpJsonObject.get("upi")
							.toString());
				if (tmpJsonObject.containsKey("uhs")) {
					if (USERHASH.equalsIgnoreCase(tmpJsonObject.get("uhs")
							.toString()))
						xstsToken.setCurrXUI(xuiEntity);
				}
				list.add(xuiEntity);
			}
			xstsToken.setXui(list);

			if (xstsToken.getCurrXUI() == null)
				xstsToken.setCurrXUI(list.get(0));
		}
		return xstsToken;

	}

	public XSTSToken parseHttpRequest(HttpServletRequest request)
			throws Exception {
		return parseHttpRequest(request, true);
	}

	public XSTSToken parseHttpRequest(HttpServletRequest request,
			boolean verifyTokenExp) throws XboxSSOAuthException {
		if (request == null) {
			logger.error("request请求为空！");
			throw new XboxSSOAuthException(-1101, "参数值为空或者不符合规范!");
		}
		String authorization = request.getHeader("authorization");
		return parseJWEString(authorization, verifyTokenExp);
	}

	public String echoPath() {
		String rootPath = PathUtil.getRootClassPath();
		String webPath = PathUtil.getWebRootPath();
		return rootPath + "|" + webPath;
	}

	private static byte[] decrypted(byte[] aesKey, byte[] iv, byte[] cipherText)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		// Security.addProvider(new BouncyCastleProvider());
		// Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec keyspec = new SecretKeySpec(aesKey, "AES");
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, keyspec, ivSpec);
		return cipher.doFinal(cipherText);
	}

	private static RSAPrivateKey getOpensslPrivateKey(String keyfile)
			throws Exception {
		File file = new File(keyfile); // keyfile key文件的地址
		FileInputStream in = new FileInputStream(file);
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		byte[] tmpbuf = new byte[1024];
		int count = 0;
		while ((count = in.read(tmpbuf)) != -1) {
			bout.write(tmpbuf, 0, count);
			tmpbuf = new byte[1024];
		}
		in.close();
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
				bout.toByteArray());
		RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory
				.generatePrivate(privateKeySpec);
		bout.close();
		return privateKey;
	}

	private void InitConfig() throws XboxSSOAuthException {
		// TODO Auto-generated method stub
		String rootPath = PathUtil.getRootClassPath() + File.separator;

		/**
		 * bestv Certificate Info
		 */
		try {
			bestvSSOCertificate = X509CertificateUtils.getCertificate(rootPath
					+ BestvSSOCertificateFile);
			bestvSSOPublicKey = X509CertificateUtils.getPublicKey(rootPath
					+ BestvSSOCertificateFile);
			bestvSSOPrivateKey = getOpensslPrivateKey(rootPath
					+ BestvSSOPrivateKeyFile);
			// MessageDigest md = MessageDigest.getInstance("sha1");
			// byte[] b = bestvSSOCertificate.getEncoded();
			// byte rawDigest[] = md.digest(bestvSSOCertificate.getEncoded());
			// String thumbPrint = JwUtility.hexify(rawDigest);
			// System.out.println(thumbPrint);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			logger.error("获取BestvSSO证书失败，路径：" + rootPath
					+ BestvSSOCertificateFile + "，错误信息：" + e.getMessage());
			throw new XboxSSOAuthException(-1102, "BestvSSO证书不可以用!");
		}

		/**
		 * xboxlive Certificate Info
		 */
		try {
			xboxSSOCertificate = X509CertificateUtils.getCertificate(rootPath
					+ XboxSSOCertificateFile);
			xboxSSOPublicKey = X509CertificateUtils.getPublicKey(rootPath
					+ XboxSSOCertificateFile);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			logger.error("获取XboxLiveSSO证书失败，路径：" + rootPath
					+ XboxSSOCertificateFile + "，错误信息：" + e.getMessage());
			throw new XboxSSOAuthException(-1103, "XboxLiveSSO证书不可用!");
		}

	}
    private static void dump(String x){
        System.out.println(x);
    }
	private static int dateCompare(String date) {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
		Calendar cal = Calendar.getInstance();
		try {
			cal.setTime(sdf.parse(date));
		} catch (ParseException e) {
			e.printStackTrace();
		}
		cal.roll(Calendar.DAY_OF_MONTH, 1);
		return cal.getTime().compareTo(new Date());
	}
    public static void main(String[] args){
        String encryptTokenSource = " XBL3.0 x=5381178999727281455;eyJlbmMiOiJBMTI4Q0JDK0hTMjU2IiwiYWxnIjoiUlNBLU9BRVAiLCJjdHkiOiJKV1QiLCJ6aXAiOiJERUYiLCJ4NXQiOiI4VmUyZ0x6NEZUYXZEN0xwV2psdXg2TTVZd2sifQ.hYOvo3BJqGXOFLIXaQkNwssLkSYdv8TjDKcEmrBjGhFku7TmGg3BekhUGNwDiReDwhGPvfYxikcLd38lj0kHxYq7_BU_yL0z5vTv5VckD0L7QORCftFA3JERobe7z7HoLzSM7LyyTR6yGAlMs-vHBF4drsjX-oWrkwo22nposlA1zkPC2NjTvNaQrmkz0qdWjKVl2jK2y-gxQXTAY5KGqQ0jWcg0Ne0_YvyyepY2SYCXTtctnNdeguXOJ3VJ0A5NWJrpPofH4AgFh5T2iLAeJR1Elf-prMLBFfBw5tv0rbEcY2HDrekRYWZ2WSQrRIAT3i_MqggPjwa3kB6vIcqHag.kM3aobqF1XjFLFvRh4FXOg.BGqHU0mtnLf_EMRUAvEiLwpdCP6ItVV4BOza-6i3pJDsLadd8XK09Wb_5vYregxdwWuIREOt55vZI655PWWandXKt193ZVSCKYg9TdkOJomoBkXCFI1PJHTg6_crtLyT6ZmOyv4sY2XbqdK1IpLkfzBr5lWO_S6bVV-FvzN3jNrIXLbVW1afF9sPrjYLQ1nUAqV804IJVIMYEdvRLnbVmq3gtrt2yIuPAB7i3xXtQItJ3MwbfEqKRLf382GaMJ8tJGdP76A_wMyZwjMs1kjGK4N1HJt0BoXEiB-bXFJLPEWXZEAm6S4euwggdQ2PVQpT0v3cTJcbQUfpJtnH7cB1fivYQrunZLxPIi6S2AoaY5XW0nYBPeMy5T1jC1luOowDsYQjsAdKgL4eflu8pNpsMX6U1TAygEJpxn_6ZLIFP2iiCRUVjVws8EAM5WiHLx94aXjFYpLwBHeIUYGoTzPUqdKrU__FHcioobgmDU9g1yHHwtVCseKNM1bHlPa6u1-kc0GiftcF7LmpnHtL-XWKvuGjIuoP52E9AC7ARk4tTT3CSafYHEiDti4zaO1x9AAZpHuRsSDJJyuiAhPaEJVOJuuPJIaP-zr8gfy_kYyf0ENehwayRLSIXZZdNzRbD5aic2iB3lHX1vnao7vUTuNGplIqugUOdc6ymxlbxsTpwttWeJM3yBL569-OGvL4-ZKIMmlDJGXNW5p6fGRVUePZi3V3fHa826UQ2ZJFLaRSRpdWsqYpsvb0HdBzDccNHphl89Q2KHAKhlkWKOYSljwFRAbKHM_O6f0jRhIY2rv3qlJa5uWKKFB-jg3JdVfmMHUdWxNF5o2vbZlJcQ-ym0VXWnnphuZ74IRq9dQ4W_G3IdxkX8I-chgoNfbYyYWsDd_Kd9GdlkPBOu00TkREQgDOqq59nuaDycIHwv7PoBlsmhcWH7vDaOW5Tl2vmFXA3A8YLlhmIhBc3fhWQ_l7KjntNGw4XribhEz_0myunb5C730vJpKrXPFlD8Q-H7H_RKRco-ZE-dXgblQZgbvbD8u1nKOHRV5PdtDiFTuil04w67h_5M1u7nRoJqtUCxNvXEyfNbZOQ0O51_Y3JZH8vq98womp78ahFwORS0m0hI8XtJgoa7j5cdCrobtZGNIs-8jeILztbbVZgFhGp-TYyLd_7Yy69MTyHFOgBaRvmFKMrHDfPKIAZ0ZU9fMjh5FDAIsY5jZToefGPiEDclNZpRwu8S-AMqqqli3-yPKzexCUJ0iTEJcnU_SJqMURWuJHlR3q.pKRsk9pEpMXAkNoUXmfzVjXRB6DKw4PROgw_WkyyiUg";
//		String encryptTokenSource = "eyJlbmMiOiJBMTI4Q0JDK0hTMjU2IiwiYWxnIjoiUlNBLU9BRVAiLCJ4NXQiOiI4VmUyZ0x6NEZUYXZEN0xwV2psdXg2TTVZd2siLCJ6aXAiOiJERUYifQ.ByRJ6f-l_MWN3N8FHrkZc6WyZc7UIWmH77ZOICWMijZ2eoRviSL6j6W3LkJKHvsmwaEZS4l1uBH0OeAJ3Bn_Zw7ckeF41_wa6nBnwhDZc_IIcQgy1K2t2QpfBaXynvMzTVAp-NckMlgeec8VH9dDOPhuxRg_tupOt2VFuDg3WdcQdBpYaA5Rh1rpLtoElF3OcS5Tg9UoLTHgRUfi8Ipv8444Lj9qvx-uGQ99GdouAm7Ari0-j1PbvL-uRNKYAzKiJDl3sZe03EFbSeErm8N4M6OhKNZAJqDk1_TIdzLdEdEA7kBUC4Tw1zvdDJ7d-fqI6WXEZdO_5rWxDw1ShzLvqw.qSxxelqD1Oxe_x5VIOH3gQ.YWt0p7QBb6KQsBTz_bR-XR9NUSYe6Ch_HXxnpXPiC_k.rLv_hMqZFJhGRXSsa8bphmg4lDyljEKAB2JuG5nWVdQ";
        String authorization = encryptTokenSource;
//		String token = JWT.me().parseOOBEJWTString(authorization, false);
//		String token = JWT.me().parseJWTString(authorization, false);
        try{
            XSTSToken token = JWT.me().parseJWEString(authorization, false);
//		System.out.println(token);
            String deviceType = token.getXdi().getDeviceType();
            String devicePairwiseID = token.getXdi().getDevicePairwiseID();
            String userPairwiseID = token.getXui().get(0).getUserPairwiseID();
            System.out.println("DeviceType:" + deviceType);
            System.out.println("DevicePairwiseID:" + devicePairwiseID);
            System.out.println("UserPairwiseID:" + userPairwiseID);
        }catch(XboxSSOAuthException e){

        }
    }
}
