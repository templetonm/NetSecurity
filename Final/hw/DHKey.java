// DHKey.java                                    -*- Java -*-
//    The DH key object
//
// Copyright(C) 1998 Robert Sexton
// You can do anything you want with this, except pretend you
// wrote it.
//
// Written   :   Robert Sexton         University of Cincinnati
//   By          
//
// Written   :   John Franco
//   For         Special Topics: Java Programming
//                           15-625-595-001      , Fall 1998
// RCS       :
//
// $Source: /home/franco/CVS/html/Courses/c653/lectures/Java/DH/DHKeyWriter.java,v $
// $Revision: 1.1 $
// $Date: 2010/01/03 17:36:55 $
//
// $Log: DHKeyWriter.java,v $
// Revision 1.1  2010/01/03 17:36:55  franco
// *** empty log message ***
//
// Revision 1.1  2008/04/20 11:46:54  franco
// *** empty log message ***
//
// Revision 0.2  1998/11/30 18:59:04  bkuhn
//   -- latest changes from Robert
//
// Revision 1.1  1998/11/30 13:53:36  robert
// Initial revision
//
// Revision 0.1  1998/11/30 03:25:28  bkuhn
//   # initial version
//

/* Modified on 11/30/2011 by Michael Templeton
 * - Moved DHKey class out of DHKeyWriter.java and into it's own file
 * - Added this class to the hw package
 * - Eclipse formatting
 * - Fix Eclipse warnings (serialVersionUID, unused import java.security.*)
 */

package hw;

import java.io.*;
import java.util.Date;
import java.math.BigInteger;

/*
 * This object is used for Public Key Exchange. 
 * The Crypto routines require it.  I haven't put the heavy
 * duty methods in here because I want it to stay small
 */
public class DHKey implements Serializable {
	private static final long serialVersionUID = -687853035510710019L;

	BigInteger p, g; /* These two make up the public Key */

	String Description;
	Date created;

	DHKey(BigInteger P, BigInteger G, String what) {
		p = P;
		g = G;

		Description = what;
		created = new Date();
	}

	/* You may wish to customize the following */
	public String toString() {
		StringBuffer scratch = new StringBuffer();
		scratch.append("Public Key(p): " + p.toString(32) + " (" + p.toString() + ")\n");
		scratch.append("Public Key(g): " + g.toString(32) + " (" + g.toString() + ")\n");
		scratch.append("Description: " + Description + "\n");
		scratch.append("Created: " + created);
		return scratch.toString();
	}
}
