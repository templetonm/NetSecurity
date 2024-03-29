/* Server.java
 * This is the Server class responsible for binding the ConnectionHandler to
 * the monitor.
 * The initial code was from Prof Franco's webpage
 * http://gauss.ececs.uc.edu/Courses/c653/homework/Specs/Server.java
 * 
 * Written by Robert Sikorski
 */

package hw;

import java.io.*;
import java.net.*;

public class Server implements Runnable {
	public static int MONITOR_PORT;
	public static int LOCAL_PORT;
	static String IDENT;
	ServerSocket s = null;
	ConnectionHandler myConHand = null;
	BufferedReader fcin = null; // file cookie in
	Thread runner = null;

	public Server(String ident, int monitor_port, int local_port) {
		try {
			MONITOR_PORT = monitor_port;
			LOCAL_PORT = local_port;
			s = new ServerSocket(LOCAL_PORT);
			IDENT = ident;
		} catch (Exception e) {
			System.out.println("Server [hwServer]: Error in Server: " + e);
			System.exit(5);
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
				int i = 0;
				while (true) {
					System.out.println("SERVER>>>:Attempting to accept socket.");
					Socket incoming = s.accept();

					System.out.println("SERVER>>>:Accepted socket.");
					myConHand = new ConnectionHandler(incoming, IDENT, i);
					myConHand.start();
					i++;
				}
			} catch (Exception e) {
				System.out.println("Server [run]: Error in Server: " + e);
			}
		}
	}
}
