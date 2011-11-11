import java.io.*;
import java.math.*;
import java.util.*;

/**
 * DecryptMessage is a program designed to take in the public key of a person
 * and use that to decrypt a message they have posted in a database. The 
 * program will read in a file that has the encrypted message and then convert
 * that message using the key to the original form. The program will output
 * the message to a file. The inputs necessary on start up are the public key, 
 * file, encrypted message file, and the output file for the message, in that 
 * order.
 *
 *
 * Created: Sun Apr 12 23:01:43 2009
 *
 * Jonathan Allan Lockhart
 * @version 1.0
 */
public class DecryptMessage {

    public static void main(String[] args) throws IOException {

	//List of variables needed for the class
	int numArgs = args.length;
	Scanner encryptMessage;
	Scanner publicKeys;
	BigInteger e = new BigInteger("0");
	BigInteger n = new BigInteger("0");
	String block = "";
	BigInteger numBlock;
	BigInteger decryptMessage;
	String message = "";
	PrintStream origMessage;

	try {
	    if (numArgs == 0) { //No arguments provided
		System.out.println("No Files Entered! Try running again!");
		System.exit(0);
	    }

	    if (numArgs < 3) { //Too few arguments provided
		System.out.println("Too Few Arguments! Takes four inputs!");
		System.exit(0);
	    }

	    if (numArgs > 3) {  //Too many arguments provided
		System.out.println("Too Many Arguments! Takes four files!");
		System.exit(0);
	    }
	
	    //Proper amount of intitial inputs were provided.
	    //Reading in the public key and encrypted messge from filee.
	    //Printing out messaage to a file.
	    else {
		publicKeys = new Scanner(new File(args[0]));
		encryptMessage = new Scanner(new File(args[1]));
		origMessage = new PrintStream(args[2]);
		
		//Get the public key from file
		e = new BigInteger(publicKeys.next());
		n = new BigInteger(publicKeys.next()); // this is actually d, but we can discard that safely.
        n = new BigInteger(publicKeys.next());
		    
		//Read in a line at a time from the encrypted message and
		//print that to an output file.
		while (encryptMessage.hasNext()) {
		    block = encryptMessage.next();
		    numBlock = new BigInteger(block);
		    decryptMessage = RSAFunctions.decrypt(e, n, numBlock);
		    message = RSAFunctions.BigIntToString(decryptMessage);
		    origMessage.print(message);
		    //System.out.println(decryptMessage);
		}
	    }
	}
	//Catch the exception if specified file on input was not found
	catch (FileNotFoundException l) {
	    System.out.println("Input does not exist! Try again!");
	    System.exit(0);
	}
    }		
}
