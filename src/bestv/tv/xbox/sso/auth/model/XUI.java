package bestv.tv.xbox.sso.auth.model;

import java.io.Serializable;

/**
 * User identity/identities
 * The claims in the user identity provide details about a user. If more than one user is logged in to the console, there will be more than one user identity in the token. If present, the user identity will be an array of claims sets (even if it is an array with one object).
 * The authorization header of the request contains the necessary information to determine which user in the token the request applies to. For additional information about processing tokens with multiple users, see Multi-user tokens.
 * @author huang.guohai
 *
 */
public class XUI implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 2696426110518245548L;
	
	private String gtg;
	private String uhs;
	private String upi;
	private String uts;
	private String lng;
	private String agg;
	private String ctr;
	private String prv;
	
	/**
	 * gtg The gamertag of the user.
	 * @return
	 */
	public String getGamertag(){
		return gtg;
	}
	/**
	 * gtg The gamertag of the user.
	 * @param val
	 */
	public void setGamertag(String val){
		gtg = val;
	}
	
	/**
	 * uhs A dynamically generated string that identifies a particular user identity within an XBL3.0 token (Xbox One). When a request applies to a specific user in the token, the client will include the appropriate user hash in the authorization header.
	 * @return
	 */
	public String getUserHash(){
		return uhs;
	}
	/**
	 * uhs A dynamically generated string that identifies a particular user identity within an XBL3.0 token (Xbox One). When a request applies to a specific user in the token, the client will include the appropriate user hash in the authorization header.
	 * @param val
	 */
	public void setUserHash(String val){
		uhs = val;
	}
	
	/**
	 * upi An anonymized identifier from Microsoft account (MSA) that represents the user. This value is unique to each partner and should be used when linking against a partner’s internal identifier for single sign on scenarios. Only available in XBL 3.0 tokens (Xbox One).
	 * @return
	 */
	public String getUserPairwiseID(){
		return upi;
	}
	/**
	 * upi An anonymized identifier from Microsoft account (MSA) that represents the user. This value is unique to each partner and should be used when linking against a partner’s internal identifier for single sign on scenarios. Only available in XBL 3.0 tokens (Xbox One).
	 * @param val
	 */
	public void setUserPairwiseID(String val){
		upi = val;
	}
	/**
	 * uts Indicates whether the user is a test user.
	 * @return
	 */
	public String getTest(){
		return uts;
	}
	/**
	 * Indicates whether the user is a test user.
	 * @param val
	 */
	public void setTest(String val){
		uts = val;
	}


}
