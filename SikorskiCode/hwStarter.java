import java.util.*;
import java.io.*;
import java.net.*;
import java.lang.*;

class hwStarter{
    // use localhost and an ssh tunnel instead.
    // tunnel with:
    //  ssh -L 8160:helios.ececs.uc.edu:8160 notabad@helios.ececs.uc.edu
    //  ssh -R 42749:localhost:42749 notabad@helios.ececs.uc.edu
    //public static String MONITOR_NAME = "helios.ececs.uc.edu";

    public static String MONITOR_NAME = "localhost";
    public static int MONITOR_PORT = 8160;
    public static String HOST_NAME = "localhost";
//    public static int LOCAL_PORT = 42749;
    
    // Takes the following arguments:
    // • int mode: 0 = launch client and server
    //             1 = launch client
    //             2 = launch server
    // • String user_name: name to be used when username is requested
    // • String user_password: password to be used to create cookies
    // • local_port: local port to be used; should match the tunnel being used
    public hwStarter(int mode, String user_name, String user_password, int local_port) throws Exception
    {
        // TODO: hwClient needs to take the user_password argument
        if (mode < 2)
        {
//            hwClient client = new hwClient(user_name, MONITOR_NAME, MONITOR_PORT, HOST_NAME, local_port);
//            client.start();
        }
        
        if (mode % 2 == 0)
        {
 //           hwServer server = new hwServer(args[0], MONITOR_PORT, LOCAL_PORT);
   //         server.start();
        }
    }

}