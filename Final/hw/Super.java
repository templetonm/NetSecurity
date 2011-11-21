package hw;

import java.io.*;
import java.math.*;

public class Super
{
	boolean waiting = false;
	boolean done = false;
	boolean encrypted = false;
	boolean thisIsClient = false;
	PrintWriter out = null;
	BufferedReader in = null;

	BufferedReader fcin = null; // file cookie in
	static String COOKIEFILE = "cookie.txt";
	static String IDENT = "";

	Thread runner = null;

	protected DHExchange dhe = null;
	protected BigInteger sPubKey = null;
	protected BigInteger Secret = null;
	protected Karn kDE = null; // karn decryption encryption

	int sMsg = -1;
	String mMsg = "";

	public String GetMonitorMessage(boolean isEncrypted, boolean isClient, int threadID)
	{
		String msg = "";

		try
		{
			msg = in.readLine();
		} catch (Exception e)
		{
			e.printStackTrace();
		}

		if (!(msg == null) && !msg.trim().equals(""))
		{
			if (isEncrypted)
			{
				// decrypt!
				msg = kDE.decrypt(msg);
				System.out.print("E>");
			}

			// Output message to screen so we know what's going on.
			if (isClient)
			{
				System.out.println("MONITOR>>>CLIENT:" + msg);
			} else
			{
				System.out.format("MONITOR>>>SERVER-%d:" + msg + "\n", threadID);
			}
		} else
		{
			waiting = true;
			done = true;
			sMsg = -10;
		}

		return msg;
	}
}
