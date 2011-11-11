/**
 * A class that implements functions to support the RSA public key
 * encryption system
 */

import java.math.*;
import java.util.*;

public class RSAFunctions {

    public static BigInteger TWO = new BigInteger("2"); // Constant value 2
    public static BigInteger ZERO = new BigInteger("0"); // Constant value 0
    public static BigInteger ONE = new BigInteger("1"); // Constant value 1

    // MODULAR EXPONENTIATION FOR ARBITRARY-PRECISION INPUTS
    public static BigInteger modExp (BigInteger a, BigInteger expon, BigInteger base)
    {
	// Pre: a and expon are nonnegative arbitrary-precision integers, and
	// base is a positive arbitrary-precision integers.
	// Post: result is set to a^expon mod base

	// i is used for stripping high-order bits from expon
	BigInteger i = new BigInteger("1");
	BigInteger r; // for holding remainders
	BigInteger q; // for holding quotient
    BigInteger result = new BigInteger("1");

	if (i.compareTo(expon) > 0)
    {
	    i = new BigInteger("0");
    }
	else
    {
	    while (expon.compareTo(i) >= 0)
        { // while expon >= i
            i = i.multiply(TWO);
	    }
	    i = i.divide(TWO);
	}

	while (i.compareTo(ZERO) > 0) { // while i > 0
	    // Each loop pass doubles the current exponent: square d
	    result = result.multiply(result);
	    result = result.mod(base);
	    // Next line starts calculation of expression in if
	    q = expon.divide(i); 
	    r = q.mod(TWO);
	    if (r.compareTo(ONE) >= 0) { 
		// If the current high-order bit of expon is 1, the current
		// exponent has been incremented: multiply by a and mod
		result = result.multiply(a);
		result = result.mod(base);
	    }
	    i = i.divide(TWO);
	}
	return result;
    }


    //GENERATE RANDOM PRIME k-BIT NUMBERS
    public static BigInteger getPrime(int numBits, Random rand){
	// Pre:  numBits is a constant positive integer and rand is a random
	//       variable with a seed value based on Java's protocol.
	// Post: Returns a prime number of between lower bound lBound and
	//       upper bound 2^numBits (number of bits is <= numBits).
	//       result and seed are modified by this function.
	
	BigInteger result = BigInteger.probablePrime(numBits, rand);
	return result;
    }
    
    // GCD ALGORITHM
    public static BigInteger gcd(BigInteger a, BigInteger b) {
	// Pre:
	// Post: d = gcd(a, b).  The value of d is modified.

	ExtEucResult res = extEuclid(a,b);

	return res.d;
    }
    
    public static String BigIntToString(BigInteger message) {
	return new String(message.toByteArray());
    }


    public static BigInteger StringToBigInt(String message) {
	return new BigInteger(message.getBytes());
    }

    /*****************************************************
     *                                                   *
     *           COMPLETE THE FOLLOWING METHODS          * 
     *                                                   *
     *****************************************************/

    // EXTENDED EUCLID ALGORITHM
    public static ExtEucResult  extEuclid(BigInteger a, BigInteger b) {
	// Pre:  Values a and b are constant, deterministic integers. Could
	//       positive or negeative.
	// Post: res.d = gcd(a,b) = a*res.x + b*res.y.
	
	ExtEucResult res = new ExtEucResult();
	res.d = new BigInteger("0");
	res.x = new BigInteger("0");
	res.y = new BigInteger("0");
	
	// BASE CASE
	if (b.compareTo(ZERO) == 0) {
	    res.d = a;
	    res.x = ONE;
	    res.y = ZERO;
	    return res;
	}

	// RECURSIVE STEP
	ExtEucResult resPrime = new ExtEucResult();
	
	resPrime = extEuclid(b, a.mod(b));
	res.d = resPrime.d;
	res.x = resPrime.y;
	res.y = (resPrime.x).subtract((a.divide(b)).multiply((resPrime.y)));
	
	return res;
    }
    
    // MODULAR EQUATION SOLVER
    public static BigInteger modEqnSolve(BigInteger a, BigInteger b,
					 BigInteger n)  {
	// RETURNS A SINGLE SOLUTION x TO THE EQUATION ax = b (mod n);
	// RETURNS -1 IF NO SOLUTION EXISTS

	//System.out.println("Calculating the inverse of e, which is d");

	BigInteger result = new BigInteger("-1"); // To allow compilation

	ExtEucResult res = new ExtEucResult();
	res.d = new BigInteger("0");
	res.x = new BigInteger("0");
	res.y = new BigInteger("0");
	
	res = extEuclid(a, n);

	if ((gcd(res.d, b)).compareTo(res.d) == 0) {
	    result = ((res.x).multiply(b.divide(res.d))).mod(n);
	}
	    
	return result;
    }

    public static BigInteger generateEncryptionKey(BigInteger phiOfN) {
	// Pre:  phiOfN is a constant integer representing the size of the 
	//       of the set of all values relatively prime to n.
	// Post: returns a BigInteger that is a number between 2^28 and 2^32
	//       that is relatively prime to phiOfN

	BigInteger e = new BigInteger("0");
	Random rand = new Random(/*92575*/);
	int sizeOfE = 32;
	BigInteger min = new BigInteger("268435456"); //2^28
	
	//Find a value of e that is relatively prime to phiOfN and is bigger 
	//than 2^28 bits. Keep doing this until a proper e is found.
	while(gcd(e, phiOfN).compareTo(ONE) != 0 
	      || e.compareTo(min) <= 0) {

	    //System.out.println("Getting a value of e");
	    
	    //Generate an e that is 2^28 bits in lengh (could have leading 0's)
	    e = new BigInteger(sizeOfE, rand);

	    //System.out.println("Checking if value is odd");

	    //If the e generated is even, change it to an odd by addind one
	    if ((e.mod(TWO)).compareTo(ZERO) == 0) {
		e = e.add(ONE);
	    }		
	}

	return e; 
    }

    public static BigInteger encrypt(BigInteger encryptKey, BigInteger n,
				     BigInteger message) {
	// Pre:  encryptKey and n are a key for the RSA public key system
        //       and message is an ascii string that has been converted to
	//       BigInteger form
	// Post: returns an encrypted version of message

	BigInteger encryptMessage = new BigInteger("0");

	encryptMessage = message.modPow(encryptKey, n);

	return encryptMessage;
    }

    public static BigInteger decrypt(BigInteger decryptKey, BigInteger n,
				     BigInteger message) {
	// Pre:  encryptKey and n are a key for the RSA public key system
        //       and message is an encrypted message in BigInteger form
	// Post: returns the decrypted version of message

	BigInteger origMessage = new BigInteger("0");

	origMessage = message.modPow(decryptKey, n);

	return origMessage;
    }

    /*******************
     *   TEST METHOD   *
     *******************/

    // MODIFY AS NEEDED TO TEST YOUR CODE.  IT ALSO PROVIDES SOME EXAMPLES.
    public static void Test() {

	//long seed = 74465;    // Choose your own seed value;  Allows
	                      // testing with consistent results
	Random rand = new Random(/*seed*/); 

	BigInteger p = getPrime(512, rand);
	BigInteger q = getPrime(512, rand);
	BigInteger a = new BigInteger("24434255243516625367695");
	BigInteger expon = p.subtract(ONE);
	BigInteger base = new BigInteger("227733448859876");
	BigInteger answer;
	BigInteger n = p.multiply(q);
	BigInteger phiOfN = (p.subtract(ONE)).multiply((q.subtract(ONE)));
	BigInteger e = generateEncryptionKey(phiOfN);
	BigInteger d = modEqnSolve(e, ONE, phiOfN);
	BigInteger ed = (e.multiply(d)).mod(phiOfN);

	answer = modExp(a,expon,p);

	System.out.println(a + " raised to the power\n" + expon + "\n(mod\n"
			   + p + ")\nis " + answer);
	expon = q.subtract(ONE); // new BigInteger("227733448859876");

	answer = modExp(a,expon,q);
	System.out.println(a + " raised to the power\n" + expon + "\n(mod\n"
			   + p + ")\nis " + answer);

	a = new BigInteger("1155");
	BigInteger b = new BigInteger("546");
	ExtEucResult res = new ExtEucResult();
	BigInteger l = new BigInteger("5000");

	res = extEuclid(a, b);
	System.out.println("The gcd of \n" + a + ",\n" + b + "\nis " + res.d
			   + "\nwhich equals\n" + a + " * " +  res.x + 
			   " + " + b + " * " + res.y);

	answer = modEqnSolve(a, b, n);
	System.out.println("For ax is equivalent to b (mod n), x is\n" 
			   + answer);
	answer = (a.multiply(answer)).mod(n);
	System.out.println("The value of ax (mod n) is\n" + answer);
	answer = b.mod(n);
	System.out.println("The value of b (mod n) is\n" + answer);

	String message = "THIS IS a really long string that needs to be converted into a big integer.";

	BigInteger intMessage = StringToBigInt(message);
	System.out.println("e = " + e);
	System.out.println("n = " + n);
	System.out.println("d = " + d);
	System.out.println("e*d mod phiOfN = " + ed);
	BigInteger encryptedMessage = encrypt(d, n, intMessage);
	BigInteger decryptedMessage = decrypt(e, n, encryptedMessage);
	String recovered = BigIntToString(decryptedMessage);

	System.out.println(message + "\n" + intMessage + "\n" +
			   encryptedMessage + "\n" + recovered);

    }

}
