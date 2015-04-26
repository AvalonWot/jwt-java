package bestv.tv.xbox.sso.auth.model;

import java.io.Serializable;
import java.util.List;

public class XSTSToken implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 6173220480153725823L;
	
	private String aud;
	private String iss;
	private String nbf;
	private String exp;
	private String sbx;
	private XDI xdi;
	private XTI xti;
	private CNF cnf;
	private List<XUI> xui;
	private XUI currXui;
	
	/**
	 * aud A JWT-reserved claim identifying the audience the JWT is intended for. (The name of your relying party.)
	 * @return
	 */
	public String getAudience(){
		return aud;
	}
	/**
	 * aud A JWT-reserved claim identifying the audience the JWT is intended for. (The name of your relying party.)
	 * @param val
	 */
	public void setAudience(String val){
		aud = val;
	}
	/**
	 * iss 获得发行商
	 * @return
	 */
	public String getIssuer(){
		return iss;
	}
	/**
	 * iss 设置发行商
	 * @param val
	 */
	public void setIssuer(String val){
		iss = val;
	}
	/**
	 * nbf A JWT-reserved claim identifying the time (UTC) before which the token must not be accepted for processing.
	 * @return
	 */
	public String getTokenIssueDate(){
		return nbf;
	}
	/**
	 * nbf A JWT-reserved claim identifying the time (UTC) before which the token must not be accepted for processing.
	 * @param val
	 */
	public void setTokenIssueDate(String val){
		nbf = val;
	}
	/**
	 * exp 获取TOKEN失效时间（UTC）
	 * @return
	 */
	public String getTokenExpiration(){
		return exp;
	}
	/**
	 * exp 设置TOKEN失效时间(UTC)
	 * @param val
	 */
	public void setTokenExpiration(String val){
		exp = val;
	}
	
	/**
	 * sbx dentifies the sandbox in which the title is being executed.
	 * @return
	 */
	public String getSandboxID(){
		return sbx;
	}
	/**
	 * sbx dentifies the sandbox in which the title is being executed.
	 * @param val
	 */
	public void setSandboxID(String val){
		sbx = val;
	}
	/**
	 * xdi Device identity claims
	 * @return
	 */
	public XDI getXdi(){
		return xdi;
	}
	
	/**
	 * xdi Device identity claims
	 * @return
	 */
	public void setXdi(XDI val){
		xdi = val;
	}
	/**
	 * 
	 * @return
	 */
	public XTI getXti(){
		return xti;
	}
	
	public void setXti(XTI val){
		xti = val;
	}
	
	public List<XUI> getXui(){
		return xui;
	}
	
	public void setXui(List<XUI> val){
		xui = val;
	}
	
	public XUI getCurrXUI(){
		return currXui;
	}
	
	public void setCurrXUI(XUI val){
		currXui = val;
	}
	
	
}
