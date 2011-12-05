package hw;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Random;

class ConnectionHandler extends Super implements Runnable {
	Socket incoming = null;
	int threadID;

	// For Transfers
	// Never used
	/*
	 * private String Recipient; private String Sender; private int Amount;
	 */
	private BigInteger N;
	private BigInteger V;
	private int ROUNDS;
	private String COOKIEFILE;
	private ArrayList<BigInteger> AUTHORIZE_SET = new ArrayList<BigInteger>();
	private ArrayList<BigInteger> SUBSET_J = new ArrayList<BigInteger>();
	private ArrayList<BigInteger> SUBSET_K = new ArrayList<BigInteger>();
	private ArrayList<Integer> SUBSET_A = new ArrayList<Integer>();
	private ArrayList<Integer> SUBSET_B = new ArrayList<Integer>();

	/*
	 * private Object authorizeArray[]; private Object subsetArrayA[]; private
	 * Object subsetArrayB[]; private Object subsetArrayK[]; private Object
	 * subsetArrayJ[];
	 */

	public ConnectionHandler(Socket sSocket, String id, int thID) {
		try {
			incoming = sSocket;
			out = new PrintWriter(incoming.getOutputStream(), true);
			in = new BufferedReader(new InputStreamReader(
					incoming.getInputStream()));
			IDENT = id;
			COOKIEFILE = IDENT + ".txt";
			threadID = thID;
			dhe = new DHExchange("DHKey");
		} catch (Exception e) {
			System.out
					.println("ConnectionHandler [ConnectionHandler]: Error in Server: "
							+ e);
		}
	}

	public void start() {
		if (runner == null) {
			runner = new Thread(this);
			runner.start();
		}
	}

	public void run() {
		while (Thread.currentThread() == runner) {
			try {
				while (!done) {
					waiting = false;

					while (!waiting) {
						mMsg = GetMonitorMessage(encrypted, thisIsClient,
								threadID);

						if (mMsg == null) {
							// Unlike in the client, where we have someone to
							// fix thing,
							// when things go blank here, we bail (this is
							// usually the
							// correct thing to do anyhow).
							break;
						}

						if (mMsg.contains("COMMAND_ERROR:")) {
							/*
							 * This needs to be tested/fixed if it doesn't hold
							 * true for all cases
							 */

							waiting = true;

						} else if (mMsg.contains("REQUIRE: IDENT")) {
							sMsg = 0;
						} else if (mMsg.contains("REQUIRE: ALIVE")) {
							sMsg = 2;
						} else if (mMsg.contains("REQUIRE: QUIT")) {
							sMsg = 3;
						} else if (mMsg.contains("REQUIRE: ROUNDS")) {
							sMsg = 10;
						} else if (mMsg.contains("REQUIRE: SUBSET_A")) {
							sMsg = 11;
						} else if (mMsg.contains("REQUIRE: TRANSFER_RESPONSE")) {
							sMsg = 12;
						} else {
							String[] tokens = mMsg.split(" ");

							if (tokens[0].equals("RESULT:")) {
								if (tokens[1].equals("IDENT")) {
									mMsg = tokens[2];
									sPubKey = new BigInteger(mMsg, 32);
									Secret = dhe.computeSecret(sPubKey);
									kDE = new Karn(Secret);
									encrypted = true;
								} else if (tokens[1].equals("PUBLIC_KEY")) {
									V = new BigInteger(tokens[2]);
									N = new BigInteger(tokens[3]);
								} else if (tokens[1].equals("AUTHORIZE_SET")) {
									AUTHORIZE_SET.clear();
									int i = 2;
									while (true) {
										try {
											// Strip the first three characters
											AUTHORIZE_SET.add(new BigInteger(tokens[i].substring(3)));
											i++;
										} catch (Exception e) {
											// AUTHORIZE_SET filled
											break;
										}
									}
								} else if (tokens[1].equals("SUBSET_K")) {
									SUBSET_K.clear();
									int i = 2;
									while (true) {
										try {
											SUBSET_K.add(new BigInteger(tokens[i]));
											i++;
										} catch (Exception e) {
											// SUBSET_K filled
											break;
										}
									}
								} else if (tokens[1].equals("SUBSET_J")) {
									SUBSET_J.clear();
									int i = 2;
									while (true) {
										try {
											SUBSET_J.add(new BigInteger(
													tokens[i]));
											i++;
										} catch (Exception e) {
											// SUBSET_J filled
											break;
										}
									}
								}
							} else if (tokens[0].equals("TRANSFER:")) {
								System.out
										.format("E>SERVER-%d>>>:Starting authentication.\n",
												threadID);
							}
						}

						if (mMsg.trim().equals("WAITING:")) {
							waiting = true;
						}
					}

					switch (sMsg) {
					case 0:
						// IDENT
						String identmsg = "IDENT " + IDENT + " "
								+ dhe.getPublicKey().toString(32);

						if (!encrypted) {
							System.out.format("SERVER-%d>>>:%s\n", threadID,
									identmsg);
							out.println(identmsg);
						} else {
							System.out.format("E>SERVER-%d>>>:%s\n", threadID,
									identmsg);
							out.println(identmsg);
						}
						break;
					case 2:
						// ALIVE
						String alivemsg = "ALIVE ";
						fcin = new BufferedReader(new FileReader(COOKIEFILE));
						alivemsg += fcin.readLine();
						fcin.close();

						if (!encrypted) {
							System.out.format("SERVER-%d>>>:%s\n", threadID,
									alivemsg);
							out.println(alivemsg);
						} else {
							System.out.format("E>SERVER-%d>>>:%s\n", threadID,
									alivemsg);
							out.println(kDE.encrypt(alivemsg));
						}
						break;
					case 3:
						// QUIT
						String quitmsg = "QUIT";

						if (!encrypted) {
							System.out.format("SERVER-%d>>>:%s\n", threadID,
									quitmsg);
							out.println(quitmsg);
						} else {
							System.out.format("E>SERVER-%d>>>:%s\n", threadID,
									quitmsg);
							out.println(kDE.encrypt(quitmsg));
						}
						break;
					case 10:
						// ROUNDS
						
						if (encrypted) {
							//Random numGenerator = new Random();
							ROUNDS = 5;
							//FAKE_ROUNDS = numGenerator.nextInt(8) + 6;
							String roundmsg = "ROUNDS " + ROUNDS;
							System.out.format("E>SERVER-%d>>>:%s\n", threadID,
									roundmsg);
							out.println(kDE.encrypt(roundmsg));
						}
						break;
					case 11:
						// SUBSET_A
						
						if (encrypted) {
							int MAX_NUM = ROUNDS / 2;
							Random rand = new Random();
							int A_SIZE = rand.nextInt(MAX_NUM) + 1;
							HashSet<Integer> tmpSet = new HashSet<Integer>();
							SUBSET_A.clear();
							SUBSET_B.clear();

							for (int i = 0; i < A_SIZE; i++) {
								tmpSet.add(rand.nextInt(ROUNDS));
							}
							SUBSET_A.addAll(tmpSet);
							Collections.sort(SUBSET_A);
							String setamsg = "SUBSET_A";
							String setbmsg = "SUBSET_B";

							for (int i = 0; i < SUBSET_A.size(); i++) {
								setamsg += " "
										+ String.valueOf(SUBSET_A.get(i));
							}
							
							for (int i = 0; i < ROUNDS; i++) {
								if (!SUBSET_A.contains(i)) {
									SUBSET_B.add(i);
									setbmsg += " " + String.valueOf(i);
								}
							}

							System.out.format("E>SERVER-%d>>>:%s\n%s\n", threadID,
									setamsg, setbmsg);
							out.println(kDE.encrypt(setamsg));
						}
						break;
					case 12:
						// TRANSFER_RESPONSE
						String transrespmsg = "TRANSFER_RESPONSE DECLINE";
						BigInteger test, actual;
						Boolean success = true;

						if (encrypted) {
							for (int i = 0; i < SUBSET_A.size(); i++) {
								test = SUBSET_K.get(i).modPow(new BigInteger("2"), N);
								actual = V.multiply(AUTHORIZE_SET.get(SUBSET_A.get(i)).pow(2)).mod(N);

								if (test.equals(actual)) {
									System.out.format(
											"K value: %s == %s Good to go!\n",
											test, actual);
								} else {
									System.out.format(
											"K value: %s != %s Failed!\n",
											test, actual);
									success = false;
								}
							}

							for (int i = 0; i < SUBSET_B.size(); i++) {
								test = SUBSET_J.get(i).modPow(new BigInteger("2"), N);
								actual = AUTHORIZE_SET.get(SUBSET_B.get(i)).modPow(new BigInteger("2"), N);

								if (test.equals(actual)) {
									System.out.format(
											"J value: %s == %s Good to go!\n",
											test, actual);
								} else {
									System.out.format(
											"J value: %s != %s Failed!\n",
											test, actual);
									success = false;
								}
							}

							// Safe to ACCEPT?
							if (success == true) {
								transrespmsg = "TRANSFER_RESPONSE ACCEPT";
							}
							
							System.out.format("E>SERVER-%d>>>:%s\n", threadID,
									transrespmsg);
							out.println(kDE.encrypt(transrespmsg));
						} else {
							transrespmsg = "TRANSFER_RESPONSE DECLINE";
							System.out.format("E>SERVER-%d>>>:%s\n", threadID,
									transrespmsg);
							out.println(kDE.encrypt(transrespmsg));
						}
						break;
					}

					if (done) {
						break;
					}
				}

				if (done) {
					break;
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		System.out.println("A server connection has exited.");
	}
}
