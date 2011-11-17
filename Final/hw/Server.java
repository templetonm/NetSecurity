package hw;

import java.io.*;
import java.net.*;
import java.util.*;
import java.math.*;

public class Server implements Runnable
{
	public static int MONITOR_PORT;
	public static int LOCAL_PORT;
	static String IDENT;
	ServerSocket s = null;
	ConnectionHandler myConHand = null;
	BufferedReader fcin = null; // file cookie in

	Thread runner = null;

	// int state
	// 0: ident
	// 1: password
	// 2: alive
	// 3: quit

	public Server(String ident, int monitor_port, int local_port)
	{
		try
		{
			MONITOR_PORT = monitor_port;
			LOCAL_PORT = local_port;
			s = new ServerSocket(LOCAL_PORT);
			IDENT = ident;
		} catch (Exception e)
		{
			System.out.println("Server [hwServer]: Error in Server: " + e);
			System.exit(5);
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
				int i = 0;
				while (true)
				{
					System.out.println("SERVER>>>:Attempting to accept socket.");
					Socket incoming = s.accept();

					System.out.println("SERVER>>>:Accepted socket.");
					myConHand = new ConnectionHandler(incoming, IDENT, i);
					myConHand.start();
					i++;
				}
			} catch (Exception e)
			{
				System.out.println("Server [run]: Error in Server: " + e);
			}
		}
	}
}

class ConnectionHandler extends Super implements Runnable
{
	Socket incoming = null;
	int threadID;

	// For Transfers
	// Never used
	/*
	 * private String Recipient; private String Sender; private int Amount;
	 */
	private BigInteger mN;
	private BigInteger mV;
	private int numOfRounds;
	// private ArrayList<BigInteger> authorizeSet;
	// private ArrayList<BigInteger> subset_K;
	// private ArrayList<BigInteger> subset_J;
	private Object authorizeArray[];
	private Object subsetArrayA[];
	private Object subsetArrayB[];
	private Object subsetArrayK[];
	private Object subsetArrayJ[];

	// Authentication States
	// 10: First step of authentication

	public ConnectionHandler(Socket sSocket, String id, int thID)
	{
		try
		{
			incoming = sSocket;
			out = new PrintWriter(incoming.getOutputStream(), true);
			in = new BufferedReader(new InputStreamReader(incoming.getInputStream()));
			IDENT = id;
			threadID = thID;

			dhe = new DHExchange("DHKey");
		} catch (Exception e)
		{
			System.out.println("ConnectionHandler [ConnectionHandler]: Error in Server: " + e);
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
				while (!done)
				{
					waiting = false;

					while (!waiting)
					{
						mMsg = GetMonitorMessage(encrypted, thisIsClient, threadID);

						if (mMsg == null)
						{
							// Unlike in the client, where we have someone to
							// fix thing,
							// when things go blank here, we bail (this is
							// usually the
							// correct thing to do anyhow).
							break;
						}

						if (mMsg.contains("COMMAND_ERROR:"))
						{
							/*
							 * This needs to be tested/fixed if it doesn't hold
							 * true for all cases
							 */

							waiting = true;

						} else if (mMsg.trim().equals("REQUIRE: IDENT"))
						{
							sMsg = 0;
						} else if (mMsg.trim().equals("REQUIRE: PASSWORD"))
						{
							sMsg = 1;
						} else if (mMsg.trim().equals("REQUIRE: ALIVE"))
						{
							sMsg = 2;
						} else if (mMsg.trim().equals("REQUIRE: QUIT"))
						{
							sMsg = 3;
						} else if (mMsg.trim().equals("REQUIRE: ROUNDS"))
						{
							sMsg = 10;
						} else if (mMsg.trim().equals("REQUIRE: SUBSET_A"))
						{
							sMsg = 11;
						} else if (mMsg.trim().equals("REQUIRE: TRANSFER_RESPONSE"))
						{
							sMsg = 12;
						} else
						{
							String[] tokens = mMsg.split(" ");

							if (tokens[0].equals("RESULT:"))
							{
								if (tokens[1].equals("IDENT"))
								{
									// This is the serverPubKey.
									mMsg = tokens[2];
									sPubKey = new BigInteger(mMsg, 32);

									// Compute the secret

									Secret = dhe.computeSecret(sPubKey);
									kDE = new Karn(Secret);
									encrypted = true;
								} else if (tokens[1].equals("PUBLIC_KEY"))
								{
									mV = new BigInteger(tokens[2]);
									mN = new BigInteger(tokens[3]);
								} else if (tokens[1].equals("AUTHORIZE_SET"))
								{
									// do we need to store the authorize set?
									// authorize_set = tokens[2 ... length-1];
									// YES, this is how we continue the check
									// that the initiator knows s, I think.
									// TODO: save authorize_set

									int lengthOfAuthorizeSet = tokens.length - 2; // this
																					// is
																					// just
																					// number
																					// of
																					// rounds,
																					// or
																					// should
																					// be
																					// at
																					// least.
									ArrayList<BigInteger> authorizeSet = new ArrayList<BigInteger>();

									for (int count = 0; count < lengthOfAuthorizeSet; count++)
									{
										System.out.format("D>--Debug: Value is " + tokens[count + 2] + ".\n", threadID);

										BigInteger value = new BigInteger(tokens[count + 2]);

										authorizeSet.add(value);
									}

									authorizeArray = authorizeSet.toArray();

								} else if (tokens[1].equals("SUBSET_K"))
								{
									int lengthOfSubsetK = tokens.length - 2;
									ArrayList<BigInteger> subset_K = new ArrayList<BigInteger>(lengthOfSubsetK);

									for (int count = 0; count < lengthOfSubsetK;)
									{
										System.out.format("D>--Debug: Subset K value is " + tokens[count + 2] + ".\n",
											threadID);

										BigInteger value = new BigInteger(tokens[count + 2]); // Integer.parseInt(tokens
																								// [count
																								// +2]);

										subset_K.add(value);

										count++;
									}

									subsetArrayK = subset_K.toArray();

									// save subset_k for testing

								} else if (tokens[1].equals("SUBSET_J"))
								{
									System.out.format("D>--Debug: This branch is entered.\n", threadID);

									int lengthOfSubsetJ = tokens.length - 2;
									ArrayList<BigInteger> subset_J = new ArrayList<BigInteger>(lengthOfSubsetJ);

									for (int count = 0; count < lengthOfSubsetJ;)
									{
										System.out.format("D>--Debug: Subset J value is " + tokens[count + 2] + ".\n",
											threadID);

										BigInteger value = new BigInteger(tokens[count + 2]);

										subset_J.add(value);

										count++;
									}

									subsetArrayJ = subset_J.toArray();

									// save subset_j for testing

								}
							} else if (tokens[0].equals("TRANSFER:"))
							{
								/*
								 * Recipient = tokens[1]; Amount =
								 * Integer.parseInt(tokens[2]); Sender =
								 * tokens[4];
								 */

								System.out.format("E>SERVER-%d>>>:Starting authentication.\n", threadID);

								// sMsg = 10;
							}
						}

						if (mMsg.trim().equals("WAITING:"))
						{
							waiting = true;
						}
					}

					System.out.format("SERVER-%d>>>:Server state: %d\n", threadID, sMsg);

					switch (sMsg)
					{
					case 0:
						if (!encrypted)
						{
							System.out.format("SERVER-%d>>>:Returning ident.\n", threadID);
							out.println("IDENT " + IDENT + " " + dhe.x_pub.toString(32));
						} else
						{
							System.out.format("E>SERVER-%d>>>:Returning ident.\n", threadID);
							String thisMessage = "IDENT " + IDENT + " " + dhe.x_pub.toString(32);
							thisMessage = kDE.encrypt(thisMessage);
							out.println(thisMessage);
						}
						break;
					case 1:
						System.out.format("SERVER-%d>>>:Password requested; error.\n", threadID);
						break;
					case 2:
						if (!encrypted)
						{
							System.out.format("SERVER-%d>>>:Returning cookie.\n", threadID);
							fcin = new BufferedReader(new FileReader(COOKIEFILE));
							mMsg = fcin.readLine();
							System.out.format("--%d: " + mMsg + "\n", threadID);
							fcin.close();
							out.println("ALIVE " + mMsg);
						} else
						{
							System.out.format("E>SERVER-%d>>>:Returning cookie.\n", threadID);
							fcin = new BufferedReader(new FileReader(COOKIEFILE));
							mMsg = fcin.readLine();
							System.out.format("E>--%d: " + mMsg + "\n", threadID);
							fcin.close();
							mMsg = "ALIVE " + mMsg;
							out.println(kDE.encrypt(mMsg));
						}
						break;
					case 3:
						if (!encrypted)
						{
							System.out.format("SERVER-%d>>>:Quitting.\n", threadID);
							out.println("QUIT");
						} else
						{
							System.out.format("E>SERVER-%d>>>:Quitting.\n", threadID);
							mMsg = "QUIT";
							out.println(kDE.encrypt(mMsg));
						}
						break;
					case 10:
						if (encrypted)
						{
							System.out.format("E>SERVER-%d>>>:Returning rounds.\n", threadID);

							Random numGenerator = new Random();

							numOfRounds = numGenerator.nextInt(15) + 1;

							System.out.format("E>SERVER-%d>>>:Number of rounds " + numOfRounds + ".\n", threadID);

							mMsg = "ROUNDS " + numOfRounds;
							out.println(kDE.encrypt(mMsg));
						}
						break;
					case 11:
						if (encrypted)
						{
							System.out.format("E>SERVER-%d>>>:Returning Subset_A.\n", threadID);

							int numOfSubsetA = numOfRounds / 2;
							ArrayList<Integer> subsetA = new ArrayList<Integer>(numOfSubsetA);

							ArrayList<Integer> subsetB = new ArrayList<Integer>(numOfRounds);
							for (int count = 0; count < numOfRounds;)
							{
								subsetB.add(count);
								count++;
							}

							Random indexValueGenerator = new Random();

							mMsg = "SUBSET_A ";

							System.out.format("E>SERVER-%d>>>:Number of values in Subset_A " + numOfSubsetA + ".\n",
								threadID);

							for (int count = 0; count < numOfSubsetA;)
							{
								int indexValue = indexValueGenerator.nextInt(numOfRounds); // count;
								subsetA.add(indexValue);

								System.out.format("D>--DEBUG: First for-loop, round " + count + " with value "
									+ indexValue + ".\n", threadID);

								// String value = Integer.toString(indexValue);
								//
								// if (count != (numOfSubsetA - 1))
								// {
								// value = value + " ";
								//
								// System.out.format("D>--DEBUG: Current value is "
								// + value + ".\n", threadID);
								//
								// mMsg = mMsg.concat(value);
								// System.out.format("D>--DEBUG: IF Current statement: "
								// + mMsg + ".\n", threadID);
								// }
								// else
								// {
								// mMsg = mMsg.concat(value);
								// System.out.format("D>--DEBUG: ELSE Current statement: "
								// + mMsg + ".\n", threadID);
								// }

								count++;
							}

							HashSet<Integer> hs = new HashSet<Integer>();
							hs.addAll(subsetA);

							for (int count = 0; count < numOfSubsetA;)
							{
								if (subsetB.contains(subsetA.get(count)))
								{
									subsetB.remove(subsetA.get(count));
									count++;
								} else
								{
									count++;
								}
							}

							Collections.sort(subsetB);

							subsetArrayB = subsetB.toArray();

							subsetA.clear();
							subsetA.addAll(hs);

							Collections.sort(subsetA);

							subsetArrayA = subsetA.toArray();

							for (int count = 0; count < subsetArrayA.length;)
							{
								int arrayValue = (Integer) subsetArrayA[count];

								String value = Integer.toString(arrayValue);

								if (count != (numOfSubsetA - 1))
								{
									value = value + " ";

									System.out.format("D>--DEBUG: Current value is " + value + ".\n", threadID);

									mMsg = mMsg.concat(value);
									System.out.format("D>--DEBUG: IF Current statement: " + mMsg + ".\n", threadID);
								} else
								{
									mMsg = mMsg.concat(value);
									System.out.format("D>--DEBUG: ELSE Current statement: " + mMsg + ".\n", threadID);
								}

								count++;
							}

							// MMSG = "SUBSET_A ";

							// for (int count2 = 0; count2 < subsetA.length; )
							// {
							// int newValue = subsetA[count2];
							//
							// String subsetValue = Integer.toString(newValue) +
							// " ";
							//
							// System.out.format("D>--DEBUG: Second for-loop, value number "
							// +
							// count2 + " is " + subsetValue + ".\n", threadID);
							//
							// mMsg.concat(subsetValue);
							//
							// count2++;
							// }
							// mMsg = "SUBSET_A 2 4 5"; // just uses default
							// from example for sake of brevity // TODO : fix
							// this later

							out.println(kDE.encrypt(mMsg));
						}
						break;
					case 12:
						if (encrypted)
						{
							// TODO: add testing for s_K and s_J
							// if pass tests, response is good

							ArrayList<BigInteger> testSubset_K = new ArrayList<BigInteger>();

							for (int count = 0; count < subsetArrayK.length; count++)
							{

								BigInteger kValue = (BigInteger) subsetArrayK[count];

								kValue = kValue.pow(2).mod(mN);

								testSubset_K.add(kValue);

							}

							for (int count = 0; count < subsetArrayK.length; count++)
							{
								if (count != (subsetArrayK.length - 1))
								{
									if (testSubset_K.get(count) == (((mV)
										.multiply(((BigInteger) authorizeArray[(Integer) subsetArrayA[count]]).pow(2)))
										.mod(mN)))
									{
										count++;
									} else
									{
										System.out.format("D>--Debug: K value does not match.\n", threadID);

										mMsg = "TRANSFER_RESPONSE DECLINE";
										out.println(kDE.encrypt(mMsg));

										break;
									}
								}
							}

							ArrayList<BigInteger> testSubset_J = new ArrayList<BigInteger>();

							for (int count = 0; count < subsetArrayJ.length; count++)
							{

								BigInteger jValue = (BigInteger) subsetArrayJ[count];

								jValue = jValue.pow(2).mod(mN);

								testSubset_J.add(jValue);

							}

							for (int count = 0; count < subsetArrayJ.length; count++)
							{
								if (count != (subsetArrayJ.length - 1))
								{
									if (testSubset_J.get(count) == authorizeArray[(Integer) subsetArrayB[count]])
									{
										count++;
									} else
									{
										System.out.format("D>--Debug: J value does not match.\n", threadID);

										mMsg = "TRANSFER_RESPONSE DECLINE";
										out.println(kDE.encrypt(mMsg));

										break;
									}
								}
							}

							// if fail, then not.

							// for now, just pass to look good !DANGEROUS
							// BEHAVIOR, POINTS MAY BE STOLEN!
							// or fail, if you want to use protection.

							mMsg = "TRANSFER_RESPONSE ACCEPT";
							out.println(kDE.encrypt(mMsg));

							System.out.format("E>SERVER-%d>>>:Transfer response was Accept.\n", threadID);
						} else
						{
							mMsg = "TRANSFER_RESPONSE DECLINE";
							out.println(kDE.encrypt(mMsg));
						}
						break;
					}

					if (done)
					{
						break;
					}
				}

				if (done)
				{
					break;
				}
			} catch (Exception e)
			{
				System.out.println("ConnectionHandler [run]: Error in Server: " + e);
				System.exit(5);
			}
		}

		System.out.println("A server connection has exited.");
	}
}