package bestv.tv.xbox.sso.auth.model;

import java.io.Serializable;
/**
 * Title identity
 * The claims in the title identity provide details about the title running on Xbox One that requested the token. The token can contain only one title identity. If present in the token, the title identity will be a simple list of claims and values.
 * @author huang.guohai
 *
 */
public class XTI implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = -4976409363335377944L;
	
	private String tvr;
	private String tid;
	
	/**
	 * tvr The title version
	 * @return
	 */
	public String getTitleVersion() {
		return tvr;
	}
	/**
	 * tvr The title version
	 * @param val
	 */
	public void setTitleVersion(String val){
		tvr = val;
	}
	/**
	 * tid The title ID
	 * @return
	 */
	public String getTitleID() {
		return tid;
	}
	/**
	 * tid The title ID
	 * @param val
	 */
	public void setTitleID(String val){
		tid = val;
	}
}
