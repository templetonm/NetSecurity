import java.io.*;
import java.net.*;
import java.util.*;
import java.lang.*;
import java.awt.*;
import java.math.*;

public class hwClient extends hwSuper implements Runnable
{
	private static String MONITOR_NAME;
	private static int MONITOR_PORT;
	private static String HOST_NAME;
	private static int HOST_PORT;
	BufferedReader uin = null; // user input
	PrintWriter fcout = null; // file cookie out
	Socket mySocket = null;

	// For Transfers
	private String Recipient;
	private String Sender;
	private int Amount;

	// int state
	// 0: ident
	// 1: passw
	// 2: cookie
	// 3: hostport
	// 5: user input
	// -1: Default to userinput to allow user attempt to fix problems if
	// possible.
	// Authentication States
	// 10: First step of authentication
	// 11: PUBLIC_KEY
	// 12: ROUNDS
	// 13: AUTHORIZE_SET
	// 14: SUBSET_A
	// 15: SUBSET_J
	// 16: SUBSET_K
	// 17: TRANSFER_RESPONSE

	public hwClient(String id, String monitor_name, int monitor_port,
			String host_name, int host_port)
	{
		try
		{
			MONITOR_NAME = monitor_name;
			MONITOR_PORT = monitor_port;
			HOST_NAME = host_name;
			HOST_PORT = host_port;
			mySocket = new Socket(MONITOR_NAME, MONITOR_PORT);
			out = new PrintWriter(mySocket.getOutputStream(), true);
			in = new BufferedReader(new InputStreamReader(
					mySocket.getInputStream()));
			uin = new BufferedReader(new InputStreamReader(System.in));
			IDENT = id;
			thisIsClient = true;

			dhe = new DiffieHellmanExchange("DHKey");
		} catch (Exception e)
		{

		}
	}

	public void start()
	{
		if (runner == null)
		{
			runner = new Thread(this);
			runner.start();
		}
	}

	public void run()
	{
		while (Thread.currentThread() == runner)
		{
			try
			{
				boolean free = false;

				while (!done)
				{
					waiting = false;

					while (!waiting)
					{
						// 0 passed for threadID because it hasn't got one.
						mMsg = GetMonitorMessage(encrypted, thisIsClient, 0);

						if (mMsg.trim().equals("REQUIRE: IDENT"))
						{
							sMsg = 0;
						} else if (mMsg.trim().equals("REQUIRE: PASSWORD"))
						{
							sMsg = 1;
						} else if (mMsg.trim().equals("REQUIRE: ALIVE"))
						{
							sMsg = 2;
						} else if (mMsg.trim().equals("REQUIRE: HOST_PORT"))
						{
							sMsg = 3;
						} else if (mMsg.trim().equals("REQUIRE: PUBLIC_KEY"))
						{
							sMsg = 11;
						} else if (mMsg.trim().equals("REQUIRE: ROUNDS"))
						{
							sMsg = 12;
						} else if (mMsg.trim().equals("REQUIRE: AUTHORIZE_SET"))
						{
							sMsg = 13;
						} else if (mMsg.trim().equals("REQUIRE: SUBSET_A"))
						{
							sMsg = 14;
						} else if (mMsg.trim().equals("REQUIRE: SUBSET_J"))
						{
							sMsg = 15;
						} else if (mMsg.trim().equals("REQUIRE: SUBSET_K"))
						{
							sMsg = 16;
						} else if (mMsg.trim().equals(
								"REQUIRE: TRANSFER_RESPONSE"))
						{
							sMsg = 17;
						} else
						{
							String[] tokens = mMsg.split(" ");

							if (tokens[0].equals("RESULT:"))
							{
								// Add check of hostport as well?
								if (tokens[1].equals("PASSWORD"))
								{
									// This is our cookie.
									System.out
											.println("Received cookie; saving.");
									mMsg = tokens[2];
									fcout = new PrintWriter(new FileWriter(
											COOKIEFILE));
									fcout.flush();
									fcout.println(mMsg);
									fcout.close();
								} else if (tokens[1].equals("IDENT"))
								{
									// This is the serverPubKey.
									mMsg = tokens[2];
									sPubKey = new BigInteger(mMsg, 32);

									// Compute the secret
									Secret = dhe.computeSecret(sPubKey);
									kDE = new hwKarn(Secret);
									encrypted = true;
								} else if (tokens[2].equals("LOCALHOST"))
								{
									System.out.println("Validated host.");
									free = true;
									sMsg = 5;
								} else if (tokens[1].equals("PUBLIC_KEY"))
								{
								} else if (tokens[1].equals("ROUNDS"))
								{
								} else if (tokens[1].equals("AUTHORIZE_SET"))
								{
								} else if (tokens[1].equals("SUBSET_A"))
								{
								} else if (tokens[1].equals("SUBSET_J"))
								{
								} else if (tokens[1].equals("SUBSET_K"))
								{
								} else
								{
									// In any other event, just let the user
									// handle things – maybe they
									// can find a way out!
									free = true;
								}
							} else if (sMsg > 9)
							{
								switch (sMsg)
								{
								case 10:
									// First response to auth
								default:
									// Oh god oh god, we're all going to die
									sMsg = 5;
									free = true;
								}
							}
						}

						// Save cookie here.

						if (free)
						{
							// Free never unsets; I'm not familiar with a
							// circumstance that would require or benefit from
							// it.
							sMsg = 5;
						}

						if (mMsg.trim().equals("WAITING:"))
						{
							waiting = true;
						}
					}

					// System.out.format("State: %d\n", sMsg);

					switch (sMsg)
					{
					case 0:
						if (!encrypted)
						{
							System.out.println("Returning ident.");
							out.println("IDENT " + IDENT + " "
									+ dhe.x_pub.toString(32));
						} else
						{
							System.out.println("E>Returning ident.");
							String thisMessage = "IDENT " + IDENT + " "
									+ dhe.x_pub.toString(32);
							thisMessage = kDE.encrypt(thisMessage);
							out.println(thisMessage);
						}
						break;
					case 1:
						if (!encrypted)
						{
							System.out.println("Returning password.");
							out.println("PASSWORD KNUT_WAS_A_BEAR");
						} else
						{
							System.out.println("E>Returning password.");
							out.println(kDE.encrypt("PASSWORD KNUT_WAS_A_BEAR"));
						}

						break;
					case 2:
						if (!encrypted)
						{
							System.out.println("Returning cookie.");
							fcin = new BufferedReader(
									new FileReader(COOKIEFILE));
							mMsg = fcin.readLine();
							System.out.println("Cookie: " + mMsg);
							fcin.close();
							out.println("ALIVE " + mMsg);
						} else
						{
							System.out.println("E>Returning cookie.");
							fcin = new BufferedReader(
									new FileReader(COOKIEFILE));
							mMsg = fcin.readLine();
							System.out.println("Cookie: " + mMsg);
							fcin.close();
							mMsg = "ALIVE " + mMsg;
							mMsg = kDE.encrypt(mMsg);
							out.println(mMsg);
						}
						break;
					case 3:
						if (!encrypted)
						{
							System.out.println("Returning host port.");
							out.println("HOST_PORT " + HOST_NAME + " "
									+ HOST_PORT);
						} else
						{
							System.out.println("E>Returning host port.");
							mMsg = "HOST_PORT " + HOST_NAME + " " + HOST_PORT;
							mMsg = kDE.encrypt(mMsg);
							out.println(mMsg);
						}
						break;
					case 5:
						if (!encrypted)
						{
							System.out.println("Sending commands!");
							System.out.println("#Input client command:");
							mMsg = uin.readLine();
							out.println(mMsg);
						} else
						{
							// This is where we can send
							// "TRANSFER_REQUEST ARG1 ARG2 FROM ARG2".
							// I wouldn't automate this.
							// I also wouldn't automate the TRANSFER_RESPONSE
							// for the sake of not
							// waving through bad requests.

							// We should automate everything after the T_Req and
							// T_Rep for the sake of brevity,
							// however.

							System.out.println("E>Sending commands!");
							System.out.println("E>#Input client command:");
							mMsg = uin.readLine();

							// tokenize this to check for transfer; we unset
							// 'free' if this is the case.
							String[] tokens = mMsg.split(" ");
							if (tokens.length == 5) // Hopefully a transfer
													// request
							{
								if (tokens[0].equals("TRANSFER_REQUEST"))
								{
									Recipient = tokens[1];
									Amount = Integer.parseInt(tokens[2]);
									Sender = tokens[4];

									free = false;
									sMsg = 10; // 10 is code for first step of
												// authentication
								}
							}

							out.println(kDE.encrypt(mMsg));
							// out.println("GET_GAME_IDENTS");
						}
						break;
					case 11:
						if (!encrypted)
						{
							System.out.println("PUBLIC_KEY");
						} else
						{
							System.out.println("E>PUBLIC_KEY");
						}
						break;
					case 12:
						if (!encrypted)
						{
							System.out.println("ROUNDS");
						} else
						{
							System.out.println("E>ROUNDS");
						}
						break;
					case 13:
						if (!encrypted)
						{
							System.out.println("AUTHORIZE_SET");
						} else
						{
							System.out.println("E>AUTHORIZE_SET");
						}
						break;
					case 14:
						if (!encrypted)
						{
							System.out.println("SUBSET_A");
						} else
						{
							System.out.println("E>SUBSET_A");
						}
						break;
					case 15:
						if (!encrypted)
						{
							System.out.println("SUBSET_J");
						} else
						{
							System.out.println("E>SUBSET_J");
						}
						break;
					case 16:
						if (!encrypted)
						{
							System.out.println("SUBSET_K");
						} else
						{
							System.out.println("E>SUBSET_K");
						}
						break;
					case 17:
						if (!encrypted)
						{
							System.out.println("TRANSFER_RESPONSE");
						} else
						{
							System.out.println("E>TRANSFER_RESPONSE");
						}
						break;
					case -1:
					}
				}
			} catch (Exception e)
			{
			}
		}
	}
}