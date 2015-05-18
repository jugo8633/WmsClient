package com.senao.wmsclient;

import java.nio.*;
import java.io.*;
import java.net.*;
import java.nio.charset.Charset;

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
	
	private final String VERSION = "WMS Client Version 0.15.05.13";
	private Socket msocket = null;

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

	public int connect(String strIP, int nPort)throws Exception
	{
		close();
		msocket = new Socket(strIP, nPort);
		return -1;
	}
	
	public void close()
	{
		if(null != msocket)
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
		if(null == msocket || msocket.isClosed())
			return false;
		return true;
	}
	/**
	 * function: authorization_request
	 * @param socket
	 * @param strDeviceId
	 * @param strClientSeq
	 * @param strAuthStatus
	 * @return
	 *  0: Unknow Error
	 *  1: Request Success
	 * -1: Packet length error 
	 * -2: Packet sequence error
	 * -3: Request Fail
	 * -4: Invalid Socket
	 * @throws ConnectException
	 * @throws IOException
	 */
	public int authorization_request( String strDeviceId, String strClientMAC, String strAuthStatus)
			throws ConnectException, IOException
	{
		if(!validSocket())
			return ERR_SOCKET_INVALID;
		
		int nResult = UNKNOW;
		final String strDelim = " ";
		final int nSequence = ++Protocol.msnSequence;
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
	
	public int authentication_request( String strClientMAC) throws ConnectException, IOException
	{
		if(!validSocket())
			return ERR_SOCKET_INVALID;
		
		int nResult = UNKNOW;
		
		final int nSequence = ++Protocol.msnSequence;
		OutputStream outSocket = msocket.getOutputStream();
		InputStream inSocket = msocket.getInputStream();

		int nLength = Protocol.WMP_HEADER_SIZE + strClientMAC.length() + 1;
		ByteBuffer buf = ByteBuffer.allocate(nLength);
		buf.putInt(nLength);
		buf.putInt(Protocol.AUTHENTICATION_REQUEST);
		buf.putInt(0);
		buf.putInt(nSequence);

		buf.put(strClientMAC.getBytes("US-ASCII"));
		buf.put((byte) 0);

		buf.flip();
		outSocket.write(buf.array());
		buf.clear();

		buf = ByteBuffer.allocate(Protocol.WMP_HEADER_SIZE + 255);
		nLength = inSocket.read(buf.array());
		buf.rewind();
		
		if (Protocol.WMP_HEADER_SIZE < nLength)
		{
			buf.order(ByteOrder.BIG_ENDIAN);
			Protocol.WMP_HEADER wmpHeader = new Protocol.WMP_HEADER();
			wmpHeader.nLength = buf.getInt(0); // offset
			wmpHeader.nId = buf.getInt(4) & 0x00ffffff;
			wmpHeader.nStatus = buf.getInt(8);
			wmpHeader.nSequence = buf.getInt(12);

			if (wmpHeader.nSequence != nSequence)
			{
				nResult = ERR_PACKET_SEQUENCE;
			}
			else
			{
				byte[] bytes = new byte[wmpHeader.nLength];
				buf.get(bytes);
				String strTemp = new String(bytes, Charset.forName("UTF-8"));
				String strBody = strTemp.substring(16);
				String[] astrBody = strBody.split(" ");
				String strMAC = astrBody[0];
				String strAuthStatus = astrBody[1];
				nResult = AUTH_N;
				if(strMAC.trim().equals(strClientMAC.trim()) && strAuthStatus.trim().equals("Y"))
				{
					nResult = AUTH_Y;
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
}
