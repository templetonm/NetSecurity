import java.util.*;
import java.io.*;
import java.net.*;
import java.lang.*;

class hw3{
    // use localhost and an ssh tunnel instead.
    // tunnel with:
    //  ssh -L 8160:helios.ececs.uc.edu:8160 notabad@helios.ececs.uc.edu
    //  ssh -R 43049:localhost:43049 notabad@helios.ececs.uc.edu
    //public static String MONITOR_NAME = "helios.ececs.uc.edu";
    public static String MONITOR_NAME = "localhost";
    public static int MONITOR_PORT = 8160;
    public static String HOST_NAME = "localhost";
//    public static int LOCAL_PORT = 43050;
    
    public static void main(String[] args)
    {
        if (args.length != 2)
        {
            System.out.println("\nbad args");
            System.out.println("usage:java hw3.java IDENT HOST_PORT\n");
        }
        else
        {
            try
            {
                hwClient client = new hwClient(args[0], MONITOR_NAME, MONITOR_PORT, HOST_NAME, Integer.parseInt(args[1]) );
                client.start();
                hwServer server = new hwServer(args[0], MONITOR_PORT, Integer.parseInt(args[1]) );
                server.start();
            }
            catch (Exception e){}
        }
    }
}