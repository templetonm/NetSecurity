package hw;

import java.io.*;
import java.util.Date;
import java.math.BigInteger;

/*
 * This object is used for Public Key Exchange. 
 * The Crypto routines require it.  I haven't put the heavy
 * duty methods in here because I want it to stay small
 */
public class DHKey implements Serializable
{
	private static final long serialVersionUID = -687853035510710019L;

	BigInteger p, g; /* These two make up the public Key */

	String Description;
	Date created;

    DHKey (BigInteger P, BigInteger G, String what)
	{
		p = P;
		g = G;

		Description = what;
		created = new Date();
	}

	/* You may wish to customize the following */
	public String toString()
	{
		StringBuffer scratch = new StringBuffer();
		scratch.append("Public Key(p): " + p.toString(32) + " (" + p.toString() + ")\n");
		scratch.append("Public Key(g): " + g.toString(32) + " (" + g.toString() + ")\n");
		scratch.append("Description: " + Description + "\n");
		scratch.append("Created: " + created);
		return scratch.toString();
	}
}
