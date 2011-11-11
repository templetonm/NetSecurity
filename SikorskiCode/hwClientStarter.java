import java.util.*;
import java.io.*;
import java.net.*;
import java.lang.*;

class hw3{
    // use localhost and an ssh tunnel instead.
    // tunnel with:
    //  ssh -L 8170:helios.ececs.uc.edu:8170 notabad@helios.ececs.uc.edu
    //  ssh -R 42849:localhost:42849 notabad@helios.ececs.uc.edu
    //public static String MONITOR_NAME = "helios.ececs.uc.edu";
    public static String MONITOR_NAME = "localhost";
    public static int MONITOR_PORT = 8170;
    public static String HOST_NAME = "localhost";
    public static int LOCAL_PORT = 42849;
    
    public static void main(String[] args)
    {
        if (args.length != 1)
        {
            System.out.println("\nbad args\n");
        }
        else
        {
            try
            {
                hwClient client = new hwClient(args[0], MONITOR_NAME, MONITOR_PORT, HOST_NAME, LOCAL_PORT);
                client.start();
            }
            catch (Exception e){}
        }
    }
}