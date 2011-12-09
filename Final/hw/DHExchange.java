/* DHExchange.java
 * The following code is from Prof Franco's webpage
 * http://gauss.ececs.uc.edu/Courses/c653/lectures/Java/DH/DiffieHellmanExchange.java
 * Formatting was added by Eclipse for readability.
 * 
 * Modified 11/30/2011 by Michael Templeton
 * - Removed filename parameter from getPublicKey
 */

package hw;

import java.security.*;
import java.math.*;
import java.io.*;

public class DHExchange {
	int keysize;
	DHKey key;
	BigInteger x, x_pub, s_secret;

	// Get the numbers p,g from file (in "key" object)
	// Generate a secure random number and create a public key from p,g
	public DHExchange(String filename) throws Exception {
		keysize = 512;
		FileInputStream fis = new FileInputStream(filename);
		ObjectInputStream oin = new ObjectInputStream(fis);
		key = (DHKey) oin.readObject();
		oin.close();
		SecureRandom sr = new SecureRandom(); // Get a secure random number
		x = new BigInteger(keysize, sr); // Generate the secure secret key
		x_pub = key.g.modPow(x, key.p); // Compute the public key from p,g
	}

	public BigInteger getPublicKey() {
		return x_pub;
	}

	// Send the client's public key to the server,
	// Get the server's public key
	// Compute the secret
	public BigInteger computeSecret(BigInteger sPubKey) throws IOException {
		s_secret = sPubKey.modPow(x, key.p);
		return s_secret;
	}
}
