/* Server.java
 * This is the Server class responsible for binding the ConnectionHandler to
 * the monitor.
 * The initial code was from Prof Franco's webpage
 * http://gauss.ececs.uc.edu/Courses/c653/homework/Specs/ActiveClient.java
 * 
 * Written by Robert Sikorski
 * 
 * Modified by Michael Templeton
 * - Added Zero-Knowledge authentication
 * - Added automatic transfer requests
 */

package hw;

import java.io.*;
import java.net.*;
import java.util.*;
import java.math.*;

public class Client extends Super implements Runnable {
	private Random random;
	private RSA rsa;
	private BigInteger N;
	private BigInteger V;
	private BigInteger S;
	private int ROUNDS;
	private int VALUE;
	private int TEMPLETON;
	private int SIKORSKI;
	private int PARK;
	private boolean START;
	String COOKIEFILE;
	String PASSWORDFILE;
	private ArrayList<BigInteger> AUTHORIZE_SET = new ArrayList<BigInteger>();
	private ArrayList<BigInteger> SUBSET_K = new ArrayList<BigInteger>();
	private ArrayList<BigInteger> SUBSET_J = new ArrayList<BigInteger>();
	private ArrayList<Integer> SUBSET_A = new ArrayList<Integer>();
	private static String MONITOR_NAME;
	private static int MONITOR_PORT;
	private static String HOST_NAME;
	private static int HOST_PORT;
	BufferedReader uin = null; // user input
	PrintWriter fcout = null; // file cookie out
	Socket mySocket = null;

	// For Transfers
	// Never used
	/*
	 * private String Recipient; private String Sender; private int Amount;
	 */

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
	// 12: AUTHORIZE_SET
	// 14: SUBSET_K

	public Client(String id, String monitor_name, int monitor_port, String host_name, int host_port, int templeton, int sikorski, int park) {
		try {
			MONITOR_NAME = monitor_name;
			MONITOR_PORT = monitor_port;
			HOST_NAME = host_name;
			HOST_PORT = host_port;
			mySocket = new Socket(MONITOR_NAME, MONITOR_PORT);
			out = new PrintWriter(mySocket.getOutputStream(), true);
			in = new BufferedReader(new InputStreamReader(mySocket.getInputStream()));
			uin = new BufferedReader(new InputStreamReader(System.in));
			IDENT = id;
			COOKIEFILE = IDENT + "COOKIE.txt";
			PASSWORDFILE = IDENT + "PASSWORD.txt";
			// Starting values
			TEMPLETON = templeton;
			SIKORSKI = sikorski;
			PARK = park;
			START = true;
			thisIsClient = true;

			try {
				dhe = new DHExchange("DHKey");
			} catch (Exception e) {
				System.out.println(String.valueOf(dhe));
				e.printStackTrace();
			}
			random = new Random();
			rsa = new RSA(random);
			N = rsa.n;
			V = rsa.V;
			S = rsa.S;
		} catch (Exception e) {

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
				boolean free = false;

				while (!done) {
					waiting = false;

					while (!waiting) {
						// 0 passed for threadID because it hasn't got one.
						mMsg = GetMonitorMessage(encrypted, thisIsClient, 0);

						if (mMsg.contains("COMMAND_ERROR:")) {
							free = true;
						} else if (mMsg.contains("REQUIRE: IDENT")) {
							sMsg = 0;
						} else if (mMsg.contains("REQUIRE: PASSWORD")) {
							sMsg = 1;
						} else if (mMsg.contains("REQUIRE: ALIVE")) {
							sMsg = 2;
						} else if (mMsg.contains("REQUIRE: HOST_PORT")) {
							sMsg = 3;
						} else if (mMsg.contains("REQUIRE: PUBLIC_KEY")) {
							sMsg = 11;
						} else if (mMsg.contains("REQUIRE: AUTHORIZE_SET")) {
							sMsg = 12;
						} else if (mMsg.contains("REQUIRE: SUBSET_J")) {
							sMsg = 13;
						} else if (mMsg.contains("REQUIRE: SUBSET_K")) {
							sMsg = 14;
						} else {
							String[] tokens = mMsg.split(" ");

							if (tokens.length != 0 && tokens[0].equals("RESULT:")) {
								// Add check of hostport as well?
								if (tokens[1].equals("PASSWORD")) {
									System.out.println("CLIENT>>>:Received cookie; saving.");
									// This is our cookie.
									mMsg = tokens[2];
									fcout = new PrintWriter(new FileWriter(COOKIEFILE));
									fcout.flush();
									fcout.println(mMsg);
									fcout.close();
								} else if (tokens[1].equals("IDENT")) {
									// This is the serverPubKey.
									mMsg = tokens[2];
									sPubKey = new BigInteger(mMsg, 32);
									// Compute the secret
									Secret = dhe.computeSecret(sPubKey);
									kDE = new Karn(Secret);
									encrypted = true;
								} else if (tokens[2].equals("LOCALHOST")) {
									/*
									 * System.out.println(
									 * "CLIENT>>>:Validated host."); free =
									 * true;
									 */
								} else if (tokens[1].equals("ROUNDS")) {
									ROUNDS = Integer.parseInt(tokens[2]);
								} else if (tokens[1].equals("SUBSET_A")) {
									// Empty the arraylist
									SUBSET_A.clear();
									// First value starts at index 2
									int i = 2;
									while (true) {
										try {
											SUBSET_A.add(Integer.parseInt(tokens[i]));
											i++;
										} catch (Exception e) {
											// SUBSET_A Filled
											break;
										}
									}
								} else if (tokens[1].equals("TRANSFER_RESPONSE")) {
									// Just go to user input logic and we'll automate it there
									sMsg = 5;
								} else {
									// In any other event, just let the user
									// handle things and maybe they
									// can find a way out!
									// free = true;
								}
							}
						}

						// Save cookie here.

						if (free) {
							// Free never unsets; I'm not familiar with a
							// circumstance that would require or benefit from
							// it.
							sMsg = 5;
						}

						if (mMsg.trim().equals("WAITING:")) {
							waiting = true;
						}
					}

					// TODO: Remove non encrypted where necessary

					switch (sMsg) {
						case 0:
							String identmsg = "IDENT " + IDENT + " " + dhe.getPublicKey().toString(32);
							if (!encrypted) {
								// System.out.println("CLIENT>>>:Returning ident... "
								// + identmsg);
								out.println(identmsg);
							} else {
								// System.out.println("E>CLIENT>>>:Returning ident... "
								// + identmsg);
								out.println(kDE.encrypt(identmsg));
							}
							break;
						case 1:
							if (!encrypted) {
								// System.out.println("CLIENT>>>:Returning password.");
								out.println("PASSWORD KNUT_WAS_A_BEAR");
							} else {
								// System.out.println("E>CLIENT>>>:Returning password.");
								out.println(kDE.encrypt("PASSWORD KNUT_WAS_A_BEAR"));
							}

							break;
						case 2:
							if (!encrypted) {
								// System.out.println("CLIENT>>>:Returning cookie.");
								fcin = new BufferedReader(new FileReader(COOKIEFILE));
								mMsg = fcin.readLine();
								// System.out.println("CLIENT>>>:Cookie: " +
								// mMsg);
								fcin.close();
								out.println("ALIVE " + mMsg);
							} else {
								// System.out.println("E>CLIENT>>>:Returning cookie.");
								fcin = new BufferedReader(new FileReader(COOKIEFILE));
								mMsg = fcin.readLine();
								// System.out.println("CLIENT>>>:Cookie: " +
								// mMsg);
								fcin.close();
								mMsg = "ALIVE " + mMsg;
								mMsg = kDE.encrypt(mMsg);
								out.println(mMsg);
							}
							break;
						case 3:
							// HOST_PORT
							if (!encrypted) {
								// System.out.println("CLIENT>>>:Returning host port.");
								out.println("HOST_PORT " + HOST_NAME + " " + HOST_PORT);
							} else {
								// System.out.println("E>CLIENT>>>:Returning host port.");
								mMsg = "HOST_PORT " + HOST_NAME + " " + HOST_PORT;
								mMsg = kDE.encrypt(mMsg);
								out.println(mMsg);
							}
							free = true;
							break;
						case 5:
							// user input
							String transmsg = "TRANSFER_REQUEST " + IDENT + " ";
							if (START == true) {
								String changepass = "CHANGE_PASSWORD ";
								fcin = new BufferedReader(new FileReader(PASSWORDFILE));
								String pass = fcin.readLine();
								fcin.close();
								changepass += pass + " ";
								Integer g = Math.abs(random.nextInt());
								fcout = new PrintWriter(new FileWriter(PASSWORDFILE));
								fcout.flush();
								fcout.println(g);
								fcout.close();
								changepass += String.valueOf(g);
								System.out.println(changepass);
								changepass = kDE.encrypt(changepass);
								out.println(changepass);
								// Predict what the correct values should be
								if (IDENT == "TEMPLETON") {
									VALUE = (int) ((TEMPLETON + PARK) * 0.01);
									transmsg += String.valueOf(PARK) + " FROM CR89";
								} else if (IDENT == "SIKORSKI") {
									VALUE = (int) ((SIKORSKI + TEMPLETON) * 0.01);
									transmsg += String.valueOf(TEMPLETON) + " FROM TEMPLETON";
								} else {
									VALUE = (int) ((PARK + SIKORSKI) * 0.01);
									transmsg += String.valueOf(SIKORSKI) + " FROM SIKORSKI";
								}
								START = false;
							} else {
								// We first passed around our initial points
								// and gained interest three times
								VALUE = (int) (VALUE + VALUE*0.01);
								VALUE = (int) (VALUE + VALUE*0.01);
								VALUE = (int) (VALUE + VALUE*0.01);
								if (IDENT == "TEMPLETON") {
									transmsg += String.valueOf(VALUE) + " FROM CR89";
								} else if (IDENT == "SIKORSKI") {
									transmsg += String.valueOf(VALUE) + " FROM TEMPLETON";
								} else {
									transmsg += String.valueOf(VALUE) + " FROM SIKORSKI";
								}
							}
							System.out.println(transmsg);
							transmsg = kDE.encrypt(transmsg);
							out.println(transmsg);
							free = false;
							break;
						case 11:
							// PUBLIC_KEY
							String keycmd = "PUBLIC_KEY " + V.toString() + " " + N.toString();
							if (!encrypted) {
								System.out.println("CLIENT>>>:" + keycmd);
								out.println(keycmd);
							} else {
								System.out.println("E>CLIENT>>>:" + keycmd);
								out.println(kDE.encrypt(keycmd));
							}
							break;
						case 12:
							// AUTHORIZATION_SET
							String authcmd = "AUTHORIZE_SET";
							// Empty the arraylist
							AUTHORIZE_SET.clear();
							BigInteger j;
							BigInteger R;
							int leftrubbish;
							int rightrubbish;

							for (int i = 0; i < ROUNDS; i++) {
								// R is a positive random number
								R = new BigInteger(String.valueOf(Math.abs(random.nextInt())));
								// j is R[i]^2 mod n
								j = R.modPow(new BigInteger("2"), N);
								// Store the actual authorize set value
								AUTHORIZE_SET.add(j);
								// Add some extra random integers to mess with other people
								// Five on the left
								leftrubbish = random.nextInt(80000) + 10001;
								// Three on the right
								rightrubbish = random.nextInt(800) + 101;
								// Command to send to the server via the monitor
								authcmd = authcmd + " " + String.valueOf(leftrubbish) + j.toString() + String.valueOf(rightrubbish);
							}
							if (!encrypted) {
								System.out.println("CLIENT>>>:" + authcmd);
								out.println(authcmd);
							} else {
								System.out.println("E>CLIENT>>>:" + authcmd);
								out.println(kDE.encrypt(authcmd));
							}
							break;
						case 13:
							// SUBSET_J
							String subjcmd = "SUBSET_J";
							// Empty the arraylist
							SUBSET_J.clear();
							BigInteger b;
							int a = 0;
							// SUBSET_A is a list of indices in order
							// Our J values include all of the indices not in SUBSET_A
							for (int i = 0; i < ROUNDS; i++) {
								if (a < SUBSET_A.size() && SUBSET_A.get(a) == i) {
									a++;
								} else {
									// R[i] mod n
									b = AUTHORIZE_SET.get(i).mod(N);
									// Add J[i] to the arraylist
									SUBSET_J.add(b);
									// Send it as is to the server via the monitor
									subjcmd = subjcmd + " " + b;
								}
							}
							if (!encrypted) {
								System.out.println("CLIENT>>>:" + subjcmd);
								out.println(subjcmd);
							} else {
								System.out.println("E>CLIENT>>>:" + subjcmd);
								out.println(kDE.encrypt(subjcmd));
							}
							break;
						case 14:
							// SUBSET_K
							String subkcmd = "SUBSET_K";
							// Empty the arraylist
							SUBSET_K.clear();
							BigInteger m;
							// SUBSET_K operates on all of the SUBSET_A indexes
							for (int i = 0; i < SUBSET_A.size(); i++) {
								// s * R[A[i]] mod n
								m = S.multiply(AUTHORIZE_SET.get(SUBSET_A.get(i))).mod(N);
								// Add K[i] to the arraylist
								SUBSET_K.add(m);
								// Send it as is to the server via the monitor
								subkcmd = subkcmd + " " + m;
							}
							if (!encrypted) {
								System.out.println("CLIENT>>>:" + subkcmd);
								out.println(subkcmd);
							} else {
								System.out.println("E>CLIENT>>>:" + subkcmd);
								out.println(kDE.encrypt(subkcmd));
							}
							break;
						case -1:
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
}
