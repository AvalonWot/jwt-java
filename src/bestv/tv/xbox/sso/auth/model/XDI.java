package bestv.tv.xbox.sso.auth.model;

import java.io.Serializable;

/**
 * Device identity
 * The claims in the device identity provide details about the device that requested the token. There can be only one device identity in the token. This means the device identity will be a simple list of claims and values.
 * @author huang.guohai
 *
 */
public class XDI implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 5294390740529805236L;
	
	private String ddm;
	private String dty;
	private String dvr;
	private String dpi;
	
	/**
	 * ddm The device debug mode (Retail, SRA, ERA).
	 * @return String
	 */
	public String getDeviceDebug(){
		return ddm;
	}
	/**
	 * ddm The device debug mode (Retail, SRA, ERA).
	 */
	public void setDeviceDebug(String val){
		ddm = val;
	}
	/**
	 * dty The type of device making the call.
	 * @return WindowsPhone, WindowsPhone7, Web, Xbox360, PC, MoLive, XboxOne
	 */
	public String getDeviceType(){
		return dty;
	}
	/**
	 * dty The type of device making the call.
	 * @return none
	 */
	public void setDeviceType(String val){
		dty = val;
	}
	/**
	 * dvr The device version.
	 * @return
	 */
	public String getDeviceVersion(){
		return dvr;
	}
	/**
	 * dvr The device version.
	 * @param val
	 */
	public void setDeviceVersion(String val){
		dvr = val;
	}
	/**
	 * dpi An anonymized identifier from Microsoft account (MSA) that represents the device. This value is unique to each partner.
	 * @return
	 */
	public String getDevicePairwiseID(){
		return dpi;
	}
	/**
	 * dpi An anonymized identifier from Microsoft account (MSA) that represents the device. This value is unique to each partner.
	 * @param val
	 */
	public void setDevicePairwiseID(String val){
		dpi = val;
	}

}
