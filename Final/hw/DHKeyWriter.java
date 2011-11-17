// DHKeyWriter.java                                    -*- Java -*-
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
//               15-625-595-001, Fall 1998
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
package hw;

import java.io.*;
import java.math.BigInteger;

public class DHKeyWriter
{
	public static void main(String args[])
	{
		try
		{
			BigInteger p = new BigInteger("563");
			BigInteger g = new BigInteger("5");
			DHKey dhout = new DHKey(p, g, "Diffie-Hellman public keys");
			FileOutputStream fos = new FileOutputStream("DHKey");
			ObjectOutputStream out = new ObjectOutputStream(fos);
			out.writeObject(dhout);
			fos.close();

			FileInputStream fin = new FileInputStream("DHKey");
			ObjectInputStream in = new ObjectInputStream(fin);
			DHKey dhin = (DHKey) in.readObject();
			System.out.println(dhin.toString());
		} catch (Exception e)
		{
			System.out.println(e.toString());
		}
	}
}