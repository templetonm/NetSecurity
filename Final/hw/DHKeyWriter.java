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
			BigInteger p = new BigInteger(
				"7897383601534681724700886135766287333879367007236994792380151951185032550914983506148400098806010880449684316518296830583436041101740143835597057941064647");
			BigInteger g = new BigInteger(
				"2333938645766150615511255943169694097469294538730577330470365230748185729160097289200390738424346682521059501689463393405180773510126708477896062227281603");
			DHKey key = new DHKey(p, g, "C653 DH key");
			FileOutputStream fos = new FileOutputStream("DHKey");
			ObjectOutputStream oos = new ObjectOutputStream(fos);
			oos.writeObject(key);
		} catch (Exception e)
		{
			System.out.println("Whoops!");
		}
	}
}
