package bestv.tv.xbox.sso.auth.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Properties;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;


public class PropertyConfig {
	private ConcurrentMap<String, Object> properties = new ConcurrentHashMap<String, Object>();
	private static PropertyConfig config = new PropertyConfig();

	private PropertyConfig() {
	}

	public static PropertyConfig me() {
		return config;
	}

	public void loadPropertyFile(String file) {
		loadPropertyFile(file, false);
	}

	public void loadPropertyFile(String file, Boolean isFullPath) {

		Properties property = new Properties();

		if (StringUtil.isBlank(file))

			throw new IllegalArgumentException(
					"Parameter of file can not be blank");

		if (file.contains(".."))

			throw new IllegalArgumentException(
					"Parameter of file can not contains \"..\"");

		InputStream inputStream = null;

		String fullFile; // String fullFile = PathUtil.getWebRootPath() + file;

		if (isFullPath == true) {
			fullFile = file;
		} else {
			if (file.startsWith(File.separator))

				fullFile = PathUtil.getWebRootPath() + File.separator
						+ "WEB-INF" + file;

			else

				fullFile = PathUtil.getWebRootPath() + File.separator
						+ "WEB-INF" + File.separator + file;
		}
		try {
			inputStream = new FileInputStream(new File(fullFile));
			property.load(inputStream);
		} catch (Exception eOne) {
			try {
				ClassLoader loader = Thread.currentThread()
						.getContextClassLoader();
				property.load(loader.getResourceAsStream(file));
			} catch (IOException eTwo) {
				throw new IllegalArgumentException(
						"Properties file loading failed: " + eTwo.getMessage());
			}
		} finally {
			try {
				if (inputStream != null)
					inputStream.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		if (property != null) {
			for (Entry<Object, Object> entry : property.entrySet()) {
				this.properties
						.put(entry.getKey().toString(), entry.getValue());
			}
		}
	}

	public String getProperty(String key) {
		if (this.properties.containsKey(key)) {
			return properties.get(key).toString();
		}
		return null;
	}

	public String getProperty(String key, String defaultValue) {
		if (this.properties.containsKey(key)) {
			return properties.get(key).toString();
		}
		return defaultValue;
	}

	public Integer getPropertyToInt(String key) {
		Integer resultInt = null;
		String resultStr = this.getProperty(key);
		if (resultStr != null)
			resultInt = Integer.parseInt(resultStr);
		return resultInt;
	}

	public Integer getPropertyToInt(String key, Integer defaultValue) {
		Integer result = getPropertyToInt(key);
		return result != null ? result : defaultValue;
	}

	public Boolean getPropertyToBoolean(String key) {
		String resultStr = this.getProperty(key);
		Boolean resultBool = null;
		if (resultStr != null) {
			if (resultStr.trim().equalsIgnoreCase("true"))
				resultBool = true;
			else if (resultStr.trim().equalsIgnoreCase("false"))
				resultBool = false;
		}
		return resultBool;
	}

	public Boolean getPropertyToBoolean(String key, boolean defaultValue) {
		Boolean result = getPropertyToBoolean(key);
		return result != null ? result : defaultValue;
	}

	// 写入properties信息
	public void writeProperties(String filePath, String parameterName,
			String parameterValue) {
		Properties prop = new Properties();
		try {
			InputStream fis = new FileInputStream(filePath);
			prop.load(fis);
			OutputStream fos = new FileOutputStream(filePath);
			prop.setProperty(parameterName, parameterValue);
			prop.store(fos, "Update '" + parameterName + "' value");
		} catch (IOException e) {
			System.err.println("Visit " + filePath + " for updating "
					+ parameterName + " value error");
		}
	}

}
