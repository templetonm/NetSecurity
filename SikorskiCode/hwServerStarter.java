import java.util.*;
import java.io.*;
import java.net.*;
import java.lang.*;

class hwServerStarter{
    // use localhost and an ssh tunnel instead.
    // tunnel with:
    //  ssh -L 8160:helios.ececs.uc.edu:8160 notabad@helios.ececs.uc.edu
    //  ssh -R 42749:localhost:42749 notabad@helios.ececs.uc.edu
    //public static String MONITOR_NAME = "helios.ececs.uc.edu";
    public static String MONITOR_NAME = "localhost";
    public static int MONITOR_PORT = 8160;
    public static String HOST_NAME = "localhost";
//    public static int LOCAL_PORT = 42749;
    
    public static void main(String[] args)
    {
        if (args.length != 2)
        {
            System.out.println("\nbad args\n");
            System.out.println("Usage: java hwServerStarter user_name local_port\n");
        }
        else
        {
            try
            {
                String user_name = args[0];
                int local_port = Integer.parseInt(args[1]);
                
                // set this up to use hwStarter instead of hwServer directly.
                
                hwServer server = new hwServer(user_name, MONITOR_PORT, local_port);
                server.start();
            }
            catch (Exception e){}
        }
    }
}