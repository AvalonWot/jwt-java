package bestv.tv.xbox.sso.auth.exception;

public class XboxSSOAuthException extends Exception {

	/** 
	* @Fields serialVersionUID : TODO 
	*/ 
	private static final long serialVersionUID = 6024375834191068506L;
	
	private int errorCode;
	
	/**
	 * 
	* @Title: XboxSSOAuthException
	* @Description:
	* @param errorCode
	* @param ex
	 */
	public XboxSSOAuthException(int errorCode, Throwable ex) {
		super(ex);
		this.errorCode = errorCode;
	}
	
	/**
	 * 
	* @Title: XboxSSOAuthException
	* @Description:
	* @param errorCode
	* @param msg
	 */
	public XboxSSOAuthException(int errorCode, String msg) {
		super(msg);
		this.errorCode = errorCode;
	}
	
	/**
	 * 
	* @Title: XboxSSOAuthException 
	* @Description: TODO
	* @param @param errorCode
	* @return void
	* @throws
	 */
	public XboxSSOAuthException(int errorCode) {
		this.errorCode = errorCode;
	}
	
	public int getErrorCode() {
		return errorCode;
	}

}
