import java.util.*;
import java.math.*;
import java.io.*;

/**
 * EncryptMessage is a program designed to take the values created by the 
 * GenerateKeys program, read them in from a file, take a message from a file
 * as well, and using the specific encryption of decryption keys, public or 
 * private, will encrypt the message in a new form that only someone with the 
 * proper key can decipher. The file inputs that are necessary on start up are
 * the key file, the message file, and the output file, in that order.
 *
 *
 * Created: Sun Apr 12 21:12:21 2009
 *
 * @author Jonathan Allan Lockhart
 * @version 1.0
 */
public class EncryptMessage {

    public static void main(String[] args) throws IOException {

	//List of variables needed for the class
	int numArgs = args.length;
	Scanner inKeys;
	String valE = "";
	String valP = "";
	String valQ = "";
	BigInteger d = new BigInteger("0");
	BigInteger n = new BigInteger("0");
	BufferedReader inMessage;
	PrintStream secretMessage;
	String block = "";
	BigInteger numBlock;
	BigInteger encryptedMessage;
	int count = 0;

	try {
	    if (numArgs == 0) { //No arguments provided
		System.out.println("No Files Entered! Try running again!");
		System.exit(0);
	    }
	    
	    if (numArgs < 3) { //Too few arguments provided
		System.out.println("Too Few Arguments! Takes three files!");
		System.exit(0);
	    }
	    
	    if (numArgs > 3) { //Too many arguments provided
		System.out.println("Too Many Arguments! Takes three files!");
		System.exit(0);
	    }
	    
	    //Proper amount of intitial inputs were provided.
	    //Reading keys from the file generated by GenerateKeys
	    else {
		inKeys = new Scanner(new File(args[0]));
		valE = inKeys.next();
		d = new BigInteger(inKeys.next());
		n = new BigInteger(inKeys.next());
		valP = inKeys.next();
		valQ = inKeys.next();
	    }
    
	    //Set the value of the input reader to that of the file containing
	    //the message to be encrypted.
	    inMessage = new BufferedReader(new FileReader(args[1]));

	    //Set the value of the output stream to that of the file the user
	    //specified as the output file.
	    secretMessage = new PrintStream(args[2]);
	    
	    //Read a character at a time from the file containing a message. 
	    //Continue to read a character as long as the file contains input.
	    //After every 64 characters encode those characters into an 
	    //encrypted message and print that to the output file. 64 
	    //characters was chosen as the block size because it is a power of
	    //2 and the fact that 2^5 * 2^3 = 2^8 = 512 bits per message. This
	    //allows the encrypted blocks to be smaller than the number of bits
	    //in n, which is required for proper encoding and decoding, plus it
	    //is an nice round number, I think.
	    //Count and block will be reset after every 64 characters.
	    while (inMessage.ready()) {
		block += (char) inMessage.read();
		count ++;
		if (count == 64) {  
		    numBlock = RSAFunctions.StringToBigInt(block);
		    encryptedMessage = RSAFunctions.encrypt(d, n, numBlock);
		    //System.out.println(numBlock);
		    secretMessage.println(encryptedMessage);
		    count = 0;
		    block = "";
		}
	    }

	    //Buffer may have characters in it although it is less than 64.
	    if (block.length() > 0) {
		numBlock = RSAFunctions.StringToBigInt(block);
		encryptedMessage = RSAFunctions.encrypt(d, n, numBlock);
		//System.out.println(numBlock);
		secretMessage.println(encryptedMessage);
	    }
	}	  
	//Catch the exception if specified file on input was not found  
	catch (FileNotFoundException c) {
	    System.out.println("File does not exist! Try again!");
	    System.exit(0);
	}
    }		    
}
