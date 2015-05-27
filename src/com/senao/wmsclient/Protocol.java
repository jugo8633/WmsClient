package com.senao.wmsclient;

public abstract class Protocol
{
	/** WMP Command **/
	static public int msnSequence = 0;
	static public final int WMP_HEADER_SIZE = 16;

	static public final int BIND_REQUEST = 0x00000001;
	static public final int BIND_RESPONSE = 0x80000001;
	static public final int UNBIND_REQUEST = 0x00000006;
	static public final int UNBIND_RESPONSE = 0x80000006;
	static public final int ENQUIRE_LINK_REQUEST = 0x00000015;
	static public final int ENQUIRE_LINK_RESPONSE = 0x80000015;
	static public final int ACCESS_LOG_REQUEST = 0x00000003;
	static public final int ACCESS_LOG_RESPONSE = 0x80000003;
	static public final int AUTHORIZATION_REQUEST = 0x00000004;
	static public final int AUTHORIZATION_RESPONSE = 0x80000004;
	static public final int AUTHENTICATION_REQUEST = 0x00000002;
	static public final int AUTHENTICATION_RESPONSE = 0x80000002;
	static public final int FIRMWARE_UPDATE_REQUEST = 0x00000007;
	static public final int FIRMWARE_UPDATE_RESPONSE = 0x80000007;
	static public final int USER_ACCOUNT_UPDATE_REQUEST = 0x00000008;
	static public final int USER_ACCOUNT_UPDATE_RESPONSE = 0x80000008;

	static public final int STATUS_ROK = 0x00000000;
	static public final int STATUS_RINVMSGLEN = 0x00000001;
	static public final int STATUS_RINVCMDLEN = 0x00000002;
	static public final int STATUS_RINVCMDID = 0x00000003;
	static public final int STATUS_RINVBNDSTS = 0x00000004;
	static public final int STATUS_RALYBND = 0x00000005;
	static public final int STATUS_RSYSERR = 0x00000008;
	static public final int STATUS_RINVSRCADR = 0x0000000A;
	static public final int STATUS_RINVDSTADR = 0x0000000B;
	static public final int STATUS_RINVMSGID = 0x0000000C;
	static public final int STATUS_RBINDFAIL = 0x0000000D;
	static public final int STATUS_RINVPASWD = 0x0000000E;
	static public final int STATUS_RINVDEVICEMAC = 0x0000000F;
	static public final int STATUS_RINVBODY = 0x00000010;
	static public final int STATUS_RINVCLIENTMAC = 0x00000011;
	static public final int STATUS_RINVURL = 0x00000012;

	static public class WMP_HEADER
	{
		int nLength;
		int nId;
		int nStatus;
		int nSequence;

		void clean()
		{
			nLength = 0;
			nId = 0;
			nStatus = 0;
			nSequence = 0;
		}
	}

	static public class WMP_AUTHENTICATION_BODY
	{
		String strClientMAC;
		String strAuthStatus;
	}

	static public class WMP_BIND_RESP_BODY
	{
		String strAuthPageUrl;
		String strDefaultUrl;
	}

	static public class WMP_ACCESS_REQ_BODY
	{
		String strClientMAC;
		String strDestAddr;
		String strDestPort;
		String strWebUrl;
	}
}
