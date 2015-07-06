package com.senao.wmsclient;

import java.nio.*;
import java.io.*;
import java.net.*;
import java.nio.charset.Charset;
import java.util.HashMap;

public class WmsClient
{
	static public final int UNKNOW = 0;
	static public final int SUCCESS = 1;
	static public final int AUTH_Y = 2;
	static public final int AUTH_N = 3;
	static public final int ERR_PACKET_LENGTH = -1;
	static public final int ERR_PACKET_SEQUENCE = -2;
	static public final int ERR_REQUEST_FAIL = -3;
	static public final int ERR_SOCKET_INVALID = -4;
	static public final int ERR_INVALID_PARAM = -5;

	private final String VERSION = "WMS Client Version 0.15.05.13";
	private Socket msocket = null;
	private final String strDelim = " ";

	public WmsClient()
	{

	}

	@Override
	protected void finalize() throws Throwable
	{
		// TODO Auto-generated method stub
		close();
		super.finalize();
	}

	@Override
	public String toString()
	{
		// TODO Auto-generated method stub
		// return super.toString();
		return VERSION;
	}

	public int connect(String strIP, int nPort) throws Exception
	{
		close();
		msocket = new Socket(strIP, nPort);
		return -1;
	}

	public void close()
	{
		if (null != msocket)
		{
			try
			{
				msocket.close();
			}
			catch (IOException e)
			{
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			msocket = null;
		}
	}

	private boolean validSocket()
	{
		if (null == msocket || msocket.isClosed())
			return false;
		return true;
	}

	private int getSequence()
	{
		++Protocol.msnSequence;
		if (0x7FFFFFFF <= Protocol.msnSequence)
		{
			Protocol.msnSequence = 0x00000001;
		}
		return Protocol.msnSequence;
	}

	/**
	 * function: authorization_request
	 * 
	 * @param socket
	 * @param strDeviceId
	 * @param strClientSeq
	 * @param strAuthStatus
	 * @return 0: Unknow Error 1: Request Success -1: Packet length error -2:
	 *         Packet sequence error -3: Request Fail -4: Invalid Socket
	 * @throws ConnectException
	 * @throws IOException
	 */
	public int authorization_request(String strDeviceId, String strClientMAC, String strAuthStatus)
			throws ConnectException, IOException
	{
		if (!validSocket())
			return ERR_SOCKET_INVALID;

		int nResult = UNKNOW;
		final int nSequence = getSequence();
		OutputStream outSocket = msocket.getOutputStream();
		InputStream inSocket = msocket.getInputStream();
		int nLength = Protocol.WMP_HEADER_SIZE + strDeviceId.length() + 1 + strClientMAC.length() + 1 + strAuthStatus.length() + 1;
		ByteBuffer buf = ByteBuffer.allocate(nLength);
		buf.putInt(nLength);
		buf.putInt(Protocol.AUTHORIZATION_REQUEST);
		buf.putInt(0);
		buf.putInt(nSequence);

		buf.put(strDeviceId.getBytes("US-ASCII"));
		buf.put(strDelim.getBytes("US-ASCII"));

		buf.put(strClientMAC.getBytes("US-ASCII"));
		buf.put(strDelim.getBytes("US-ASCII"));

		buf.put(strAuthStatus.getBytes("US-ASCII"));
		buf.put((byte) 0);

		buf.flip();
		outSocket.write(buf.array());
		buf.clear();

		buf = ByteBuffer.allocate(nLength);
		nLength = inSocket.read(buf.array());
		buf.rewind();
		Protocol.WMP_HEADER wmpResp = new Protocol.WMP_HEADER();
		if (Protocol.WMP_HEADER_SIZE == nLength)
		{
			buf.order(ByteOrder.BIG_ENDIAN);
			wmpResp.nLength = buf.getInt(0); // offset
			wmpResp.nId = buf.getInt(4) & 0x00ffffff;
			wmpResp.nStatus = buf.getInt(8);
			wmpResp.nSequence = buf.getInt(12);

			if (wmpResp.nSequence != nSequence)
			{
				nResult = ERR_PACKET_SEQUENCE;
			}
			else
			{
				if (Protocol.STATUS_ROK == wmpResp.nStatus)
				{
					nResult = SUCCESS;
				}
				else
				{
					nResult = ERR_REQUEST_FAIL;
				}
			}
		}
		else
		{
			nResult = ERR_PACKET_LENGTH;
		}
		buf.clear();
		buf = null;
		return nResult;
	}

	public int authentication_request(String strClientMAC, HashMap<String, String> respData) throws ConnectException, IOException
	{
		if (!validSocket())
			return ERR_SOCKET_INVALID;

		if (null == strClientMAC || null == respData)
		{
			return ERR_INVALID_PARAM;
		}

		int nResult = UNKNOW;
		final int nSequence = getSequence();
		OutputStream outSocket = msocket.getOutputStream();
		InputStream inSocket = msocket.getInputStream();

		int nLength = Protocol.WMP_HEADER_SIZE + strClientMAC.length() + 1;
		ByteBuffer buf = ByteBuffer.allocate(nLength);
		buf.putInt(nLength);
		buf.putInt(Protocol.AUTHENTICATION_REQUEST);
		buf.putInt(Protocol.STATUS_ROK);
		buf.putInt(nSequence);

		respData.put("REQ_LENGTH", String.valueOf(nLength));
		respData.put("REQ_ID", "authentication_request");
		respData.put("REQ_STATUS", "0");
		respData.put("REQ_SEQUENCE", String.valueOf(nSequence));

		buf.put(strClientMAC.getBytes("US-ASCII"));
		buf.put((byte) 0);
		respData.put("REQ_BODY_CLIENT_MAC", strClientMAC);

		buf.flip();
		outSocket.write(buf.array());
		buf.clear();

		buf = ByteBuffer.allocate(Protocol.WMP_HEADER_SIZE + 255);
		nLength = inSocket.read(buf.array());
		buf.rewind();
		if (Protocol.WMP_HEADER_SIZE < nLength)
		{
			nResult = checkResponse(buf, nSequence);

			buf.order(ByteOrder.BIG_ENDIAN);
			respData.put("RESP_LENGTH", String.valueOf(buf.getInt(0)));
			respData.put("RESP_ID", String.valueOf(buf.getInt(4) & 0x00ffffff));
			respData.put("RESP_STATUS", String.valueOf(buf.getInt(8)));
			respData.put("RESP_SEQUENCE", String.valueOf(buf.getInt(12)));

			if (SUCCESS == nResult)
			{
				byte[] bytes = new byte[buf.getInt(0)];
				buf.get(bytes);
				String strTemp = new String(bytes, Charset.forName("UTF-8"));
				String strBody = strTemp.substring(16);
				String[] astrBody = strBody.split(" ");
				respData.put("RESP_BODY_CLIENT_MAC", astrBody[0]);
				respData.put("RESP_BODY_AUTH_STATUS", astrBody[1]);
				bytes = null;
			}
		}
		else
		{
			nResult = ERR_PACKET_LENGTH;
		}
		buf.clear();
		buf = null;
		return nResult;
	}

	public int userAccountUpdate(final String strClientMAC, final String strAccount) throws ConnectException, IOException
	{
		if (!validSocket())
			return ERR_SOCKET_INVALID;

		if (null == strClientMAC || null == strAccount)
		{
			return ERR_INVALID_PARAM;
		}

		int nResult = UNKNOW;
		final int nSequence = getSequence();
		OutputStream outSocket = msocket.getOutputStream();
		InputStream inSocket = msocket.getInputStream();

		int nLength = Protocol.WMP_HEADER_SIZE + strClientMAC.length() + 1 + strAccount.length() + 1;
		ByteBuffer buf = ByteBuffer.allocate(nLength);
		buf.putInt(nLength);
		buf.putInt(Protocol.USER_ACCOUNT_UPDATE_REQUEST);
		buf.putInt(Protocol.STATUS_ROK);
		buf.putInt(nSequence);

		buf.put(strClientMAC.getBytes("US-ASCII"));
		buf.put(strDelim.getBytes("US-ASCII"));

		buf.put(strAccount.getBytes("US-ASCII"));
		buf.put((byte) 0);

		buf.flip();
		outSocket.write(buf.array());
		buf.clear();

		buf = ByteBuffer.allocate(Protocol.WMP_HEADER_SIZE + 1);
		nLength = inSocket.read(buf.array());
		buf.rewind();

		if (Protocol.WMP_HEADER_SIZE == nLength)
		{
			Protocol.WMP_HEADER wmpResp = new Protocol.WMP_HEADER();
			buf.order(ByteOrder.BIG_ENDIAN);
			wmpResp.nLength = buf.getInt(0); // offset
			wmpResp.nId = buf.getInt(4) & 0x00ffffff;
			wmpResp.nStatus = buf.getInt(8);
			wmpResp.nSequence = buf.getInt(12);

			if (wmpResp.nSequence != nSequence)
			{
				nResult = ERR_PACKET_SEQUENCE;
			}
			else
			{
				if (Protocol.STATUS_ROK == wmpResp.nStatus)
				{
					nResult = SUCCESS;
				}
				else
				{
					nResult = ERR_REQUEST_FAIL;
				}
			}
			wmpResp = null;
		}
		else
		{
			nResult = ERR_PACKET_LENGTH;
		}
		buf.clear();
		buf = null;

		return nResult;
	}

	public int bind_request(final String strDeviceMAC, HashMap<String, String> respData)
			throws ConnectException, IOException
	{
		if (!validSocket())
			return ERR_SOCKET_INVALID;

		if (null == strDeviceMAC || null == respData)
		{
			return ERR_INVALID_PARAM;
		}

		int nResult = UNKNOW;
		final int nSequence = getSequence();
		OutputStream outSocket = msocket.getOutputStream();
		InputStream inSocket = msocket.getInputStream();

		int nLength = Protocol.WMP_HEADER_SIZE + strDeviceMAC.length() + 1;
		ByteBuffer buf = ByteBuffer.allocate(nLength);
		buf.putInt(nLength);
		buf.putInt(Protocol.BIND_REQUEST);
		buf.putInt(Protocol.STATUS_ROK);
		buf.putInt(nSequence);

		respData.put("REQ_LENGTH", String.valueOf(nLength));
		respData.put("REQ_ID", "bind_request");
		respData.put("REQ_STATUS", "0");
		respData.put("REQ_SEQUENCE", String.valueOf(nSequence));

		buf.put(strDeviceMAC.getBytes("US-ASCII"));
		buf.put((byte) 0);

		buf.flip();
		outSocket.write(buf.array());
		buf.clear();

		buf = ByteBuffer.allocate(Protocol.WMP_HEADER_SIZE + 255);
		nLength = inSocket.read(buf.array());
		buf.rewind();
		if (Protocol.WMP_HEADER_SIZE < nLength)
		{
			nResult = checkResponse(buf, nSequence);

			buf.order(ByteOrder.BIG_ENDIAN);
			respData.put("RESP_LENGTH", String.valueOf(buf.getInt(0)));
			respData.put("RESP_ID", String.valueOf(buf.getInt(4) & 0x00ffffff));
			respData.put("RESP_STATUS", String.valueOf(buf.getInt(8)));
			respData.put("RESP_SEQUENCE", String.valueOf(buf.getInt(12)));

			if (SUCCESS == nResult)
			{
				byte[] bytes = new byte[buf.getInt(0)];
				buf.get(bytes);
				String strTemp = new String(bytes, Charset.forName("UTF-8"));
				String strBody = strTemp.substring(16);
				String[] astrBody = strBody.split(" ");
				respData.put("RESP_BODY_AUTH_PAGE", astrBody[0]);
				respData.put("RESP_BODY_DEFAULT_URL", astrBody[1]);
				bytes = null;
			}
		}
		else
		{
			nResult = ERR_PACKET_LENGTH;
		}
		buf.clear();
		buf = null;
		return nResult;
	}

	public int unbind_request(HashMap<String, String> respData) throws ConnectException, IOException
	{
		if (!validSocket())
			return ERR_SOCKET_INVALID;

		if (null == respData)
		{
			return ERR_INVALID_PARAM;
		}

		int nResult = UNKNOW;
		final int nSequence = getSequence();
		OutputStream outSocket = msocket.getOutputStream();
		InputStream inSocket = msocket.getInputStream();

		int nLength = Protocol.WMP_HEADER_SIZE;
		ByteBuffer buf = ByteBuffer.allocate(nLength);
		buf.putInt(nLength);
		buf.putInt(Protocol.UNBIND_REQUEST);
		buf.putInt(Protocol.STATUS_ROK);
		buf.putInt(nSequence);

		respData.put("REQ_LENGTH", String.valueOf(nLength));
		respData.put("REQ_ID", "unbind_request");
		respData.put("REQ_STATUS", "0");
		respData.put("REQ_SEQUENCE", String.valueOf(nSequence));

		buf.flip();
		outSocket.write(buf.array());
		buf.clear();

		buf = ByteBuffer.allocate(Protocol.WMP_HEADER_SIZE);
		nLength = inSocket.read(buf.array());
		buf.rewind();
		if (Protocol.WMP_HEADER_SIZE == nLength)
		{
			nResult = checkResponse(buf, nSequence);
			buf.order(ByteOrder.BIG_ENDIAN);
			respData.put("RESP_LENGTH", String.valueOf(buf.getInt(0)));
			respData.put("RESP_ID", String.valueOf(buf.getInt(4) & 0x00ffffff));
			respData.put("RESP_STATUS", String.valueOf(buf.getInt(8)));
			respData.put("RESP_SEQUENCE", String.valueOf(buf.getInt(12)));
		}
		else
		{
			nResult = ERR_PACKET_LENGTH;
		}
		buf.clear();
		buf = null;
		return nResult;
	}

	public int firmware_update_request(final String strUrl) throws ConnectException, IOException
	{
		if (!validSocket())
			return ERR_SOCKET_INVALID;

		int nResult = UNKNOW;
		final int nSequence = getSequence();
		OutputStream outSocket = msocket.getOutputStream();
		InputStream inSocket = msocket.getInputStream();

		int nLength = Protocol.WMP_HEADER_SIZE + strUrl.length() + 1;
		ByteBuffer buf = ByteBuffer.allocate(nLength);

		/** WMP Header **/
		buf.putInt(nLength);
		buf.putInt(Protocol.FIRMWARE_UPDATE_REQUEST);
		buf.putInt(Protocol.STATUS_ROK);
		buf.putInt(nSequence);

		/** WMP Body **/
		buf.put(strUrl.getBytes("US-ASCII"));
		buf.put((byte) 0);

		buf.flip();
		outSocket.write(buf.array());
		buf.clear();

		buf = ByteBuffer.allocate(nLength);
		nLength = inSocket.read(buf.array());
		buf.rewind();
		if (Protocol.WMP_HEADER_SIZE == nLength)
		{
			nResult = checkResponse(buf, nSequence);
		}
		else
		{
			nResult = ERR_PACKET_LENGTH;
		}
		buf.clear();
		buf = null;
		return nResult;
	}

	public int enquire_request(HashMap<String, String> respData) throws ConnectException, IOException
	{
		if (!validSocket())
			return ERR_SOCKET_INVALID;

		if (null == respData)
		{
			return ERR_INVALID_PARAM;
		}

		int nResult = UNKNOW;
		final int nSequence = getSequence();
		OutputStream outSocket = msocket.getOutputStream();
		InputStream inSocket = msocket.getInputStream();

		int nLength = Protocol.WMP_HEADER_SIZE;
		ByteBuffer buf = ByteBuffer.allocate(nLength);
		buf.putInt(nLength);
		buf.putInt(Protocol.ENQUIRE_LINK_REQUEST);
		buf.putInt(Protocol.STATUS_ROK);
		buf.putInt(nSequence);

		respData.put("REQ_LENGTH", String.valueOf(nLength));
		respData.put("REQ_ID", "enquire_link_request");
		respData.put("REQ_STATUS", "0");
		respData.put("REQ_SEQUENCE", String.valueOf(nSequence));

		buf.flip();
		outSocket.write(buf.array());
		buf.clear();

		buf = ByteBuffer.allocate(Protocol.WMP_HEADER_SIZE);
		nLength = inSocket.read(buf.array());
		buf.rewind();
		if (Protocol.WMP_HEADER_SIZE == nLength)
		{
			nResult = checkResponse(buf, nSequence);
			buf.order(ByteOrder.BIG_ENDIAN);
			respData.put("RESP_LENGTH", String.valueOf(buf.getInt(0)));
			respData.put("RESP_ID", String.valueOf(buf.getInt(4) & 0x00ffffff));
			respData.put("RESP_STATUS", String.valueOf(buf.getInt(8)));
			respData.put("RESP_SEQUENCE", String.valueOf(buf.getInt(12)));
		}
		else
		{
			nResult = ERR_PACKET_LENGTH;
		}
		buf.clear();
		buf = null;
		return nResult;
	}

	public int client_reboot_request(HashMap<String, String> respData) throws ConnectException, IOException
	{
		if (!validSocket())
			return ERR_SOCKET_INVALID;

		if (null == respData)
		{
			return ERR_INVALID_PARAM;
		}

		int nResult = UNKNOW;
		final int nSequence = getSequence();
		OutputStream outSocket = msocket.getOutputStream();
		InputStream inSocket = msocket.getInputStream();

		int nLength = Protocol.WMP_HEADER_SIZE;
		ByteBuffer buf = ByteBuffer.allocate(nLength);
		buf.putInt(nLength);
		buf.putInt(Protocol.CLIENT_REBOOT_REQUEST);
		buf.putInt(Protocol.STATUS_ROK);
		buf.putInt(nSequence);

		respData.put("REQ_LENGTH", String.valueOf(nLength));
		respData.put("REQ_ID", "client_reboot_request");
		respData.put("REQ_STATUS", "0");
		respData.put("REQ_SEQUENCE", String.valueOf(nSequence));

		buf.flip();
		outSocket.write(buf.array());
		buf.clear();

		buf = ByteBuffer.allocate(Protocol.WMP_HEADER_SIZE);
		nLength = inSocket.read(buf.array());
		buf.rewind();
		if (Protocol.WMP_HEADER_SIZE == nLength)
		{
			nResult = checkResponse(buf, nSequence);
			buf.order(ByteOrder.BIG_ENDIAN);
			respData.put("RESP_LENGTH", String.valueOf(buf.getInt(0)));
			respData.put("RESP_ID", String.valueOf(buf.getInt(4) & 0x00ffffff));
			respData.put("RESP_STATUS", String.valueOf(buf.getInt(8)));
			respData.put("RESP_SEQUENCE", String.valueOf(buf.getInt(12)));
		}
		else
		{
			nResult = ERR_PACKET_LENGTH;
		}
		buf.clear();
		buf = null;
		return nResult;
	}

	public int access_log_request(final String strClientMAC, final String strDestAddr, final String strDestPort, final String strWebUrl,
			HashMap<String, String> respData)
			throws ConnectException, IOException
	{
		if (!validSocket())
			return ERR_SOCKET_INVALID;

		if (null == respData || null == strClientMAC || null == strDestAddr || null == strDestPort || null == strWebUrl)
		{
			return ERR_INVALID_PARAM;
		}

		String strDeviceMAC = "simulator";

		int nResult = UNKNOW;
		final int nSequence = getSequence();
		OutputStream outSocket = msocket.getOutputStream();
		InputStream inSocket = msocket.getInputStream();

		int nLength = Protocol.WMP_HEADER_SIZE + strDeviceMAC.length() + 1 + strClientMAC.length() + 1 + strDestAddr.length() + 1
				+ strDestPort.length() + 1 + strWebUrl.length() + 1;
		ByteBuffer buf = ByteBuffer.allocate(nLength);
		buf.putInt(nLength);
		buf.putInt(Protocol.ACCESS_LOG_REQUEST);
		buf.putInt(0);
		buf.putInt(nSequence);

		respData.put("REQ_LENGTH", String.valueOf(nLength));
		respData.put("REQ_ID", "access_log_request");
		respData.put("REQ_STATUS", "0");
		respData.put("REQ_SEQUENCE", String.valueOf(nSequence));

		buf.put(strDeviceMAC.getBytes("US-ASCII"));
		buf.put(strDelim.getBytes("US-ASCII"));
		respData.put("REQ_BODY_DEVICE_MAC", strDeviceMAC);

		buf.put(strClientMAC.getBytes("US-ASCII"));
		buf.put(strDelim.getBytes("US-ASCII"));
		respData.put("REQ_BODY_CLIENT_MAC", strClientMAC);

		buf.put(strDestAddr.getBytes("US-ASCII"));
		buf.put(strDelim.getBytes("US-ASCII"));
		respData.put("REQ_BODY_DEST_ADDR", strDestAddr);

		buf.put(strDestPort.getBytes("US-ASCII"));
		buf.put(strDelim.getBytes("US-ASCII"));
		respData.put("REQ_BODY_DEST_PORT", strDestPort);

		buf.put(strWebUrl.getBytes("US-ASCII"));
		buf.put((byte) 0);
		respData.put("REQ_BODY_WEB_URL", strWebUrl);

		buf.flip();
		outSocket.write(buf.array());
		buf.clear();

		buf = ByteBuffer.allocate(Protocol.WMP_HEADER_SIZE);
		nLength = inSocket.read(buf.array());
		buf.rewind();
		if (Protocol.WMP_HEADER_SIZE == nLength)
		{
			nResult = checkResponse(buf, nSequence);
			buf.order(ByteOrder.BIG_ENDIAN);
			respData.put("RESP_LENGTH", String.valueOf(buf.getInt(0)));
			respData.put("RESP_ID", String.valueOf(buf.getInt(4) & 0x00ffffff));
			respData.put("RESP_STATUS", String.valueOf(buf.getInt(8)));
			respData.put("RESP_SEQUENCE", String.valueOf(buf.getInt(12)));
		}
		else
		{
			nResult = ERR_PACKET_LENGTH;
		}
		buf.clear();
		buf = null;
		return nResult;
	}

	public int config_request(final String strItem, final String strValue, HashMap<String, String> respData) throws ConnectException,
			IOException
	{
		if (!validSocket())
			return ERR_SOCKET_INVALID;

		if (null == respData || null == strItem || null == strValue)
		{
			return ERR_INVALID_PARAM;
		}

		int nResult = UNKNOW;
		final int nSequence = getSequence();
		OutputStream outSocket = msocket.getOutputStream();
		InputStream inSocket = msocket.getInputStream();

		int nLength = Protocol.WMP_HEADER_SIZE + strItem.length() + 1 + strValue.length() + 1;
		ByteBuffer buf = ByteBuffer.allocate(nLength);
		buf.putInt(nLength);
		buf.putInt(Protocol.CONFIG_REQUEST);
		buf.putInt(0);
		buf.putInt(nSequence);

		respData.put("REQ_LENGTH", String.valueOf(nLength));
		respData.put("REQ_ID", "config_request");
		respData.put("REQ_STATUS", "0");
		respData.put("REQ_SEQUENCE", String.valueOf(nSequence));

		buf.put(strItem.getBytes("US-ASCII"));
		buf.put(strDelim.getBytes("US-ASCII"));
		respData.put("REQ_BODY_CONFIG_ITEM", strItem);

		buf.put(strValue.getBytes("US-ASCII"));
		buf.put((byte) 0);
		respData.put("REQ_BODY_CONFIG_VALUE", strValue);

		buf.flip();
		outSocket.write(buf.array());
		buf.clear();

		buf = ByteBuffer.allocate(Protocol.WMP_HEADER_SIZE);
		nLength = inSocket.read(buf.array());
		buf.rewind();
		
		if (Protocol.WMP_HEADER_SIZE == nLength)
		{
			nResult = checkResponse(buf, nSequence);
			buf.order(ByteOrder.BIG_ENDIAN);
			respData.put("RESP_LENGTH", String.valueOf(buf.getInt(0)));
			respData.put("RESP_ID", String.valueOf(buf.getInt(4) & 0x00ffffff));
			respData.put("RESP_STATUS", String.valueOf(buf.getInt(8)));
			respData.put("RESP_SEQUENCE", String.valueOf(buf.getInt(12)));
		}
		else
		{
			nResult = ERR_PACKET_LENGTH;
		}
		buf.clear();
		buf = null;
		return nResult;
	}

	private int checkResponse(ByteBuffer buf, int nSequence)
	{
		int nResult = UNKNOW;

		Protocol.WMP_HEADER wmpResp = new Protocol.WMP_HEADER();
		buf.order(ByteOrder.BIG_ENDIAN);
		wmpResp.nLength = buf.getInt(0); // offset
		wmpResp.nId = buf.getInt(4) & 0x00ffffff;
		wmpResp.nStatus = buf.getInt(8);
		wmpResp.nSequence = buf.getInt(12);

		if (wmpResp.nSequence != nSequence)
		{
			nResult = ERR_PACKET_SEQUENCE;
		}
		else
		{
			if (Protocol.STATUS_ROK == wmpResp.nStatus)
			{
				nResult = SUCCESS;
			}
			else
			{
				nResult = ERR_REQUEST_FAIL;
			}
		}
		wmpResp = null;
		return nResult;
	}
}
