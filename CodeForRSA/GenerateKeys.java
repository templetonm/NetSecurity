import java.math.*;
import java.util.*;

/**
 * GenerateKeys is a class that uses the functions in RSAFunctions to generate
 * two primes p and q which are used to get the values d, e, and n. e and n 
 * will go on to be used as the public key will the combination of d and n is
 * the private key.
 *
 *
 * Created: Sun Apr 12 17:57:57 2009
 *
 * @author Jonathan Allan Lockhart
 * @version 1.0
 */
public class GenerateKeys {

    public static void main(String[] args) {

	//long seed = 92575; //For debugging and testing only

	Random rand = new Random(/*seed*/);

	//Generate the values of p and q
	BigInteger p = RSAFunctions.getPrime(1024, rand);
	BigInteger q = RSAFunctions.getPrime(1024, rand);

	//Generate n using p and q
	//n = p * q
	BigInteger n = p.multiply(q);

	//Find phi(n) using n, p, and q
	//phi(n) = n * (1-1/p) * (1 - 1/q) = (p-1) * (q-1)
	BigInteger phiOfN = (p.subtract(RSAFunctions.ONE)).multiply((q.subtract(RSAFunctions.ONE)));

	//Using phiOfN, use the RSAFunction encryptKey method to find the e
	//for the public key combination.
	BigInteger e = RSAFunctions.generateEncryptionKey(phiOfN);

	//Using e, use the function modEqnSolve to calculate the inverse of e,
	//d, which will give the other component to the private key pair.
	BigInteger d = RSAFunctions.modEqnSolve(e, RSAFunctions.ONE, phiOfN);

	//Print out the values just obtained in the order of e,d,n,p,q
	//Make sure to pipe the output to a file with a name of your choice
	System.out.println(e);
	System.out.println(d);
	System.out.println(n);
	System.out.println(p);
	System.out.println(q);
    }
}
