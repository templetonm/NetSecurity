package hw;

public class Main
{
	public static String MONITOR_NAME = "gauss.ececs.uc.edu";
	public static int MONITOR_PORT = 8150;
	public static String HOST_NAME = "localhost";

	public static void main(String[] args)
	{
		if (args.length != 1)
		{
			System.out.println("\nbad args");
			System.out.println("usage:java hw3.java TEMPLETON_STARTING_VALUE SIKORSKI_STARTING_VALUE CR89_STARTING_VALUE\n");
		} else
		{
			try
			{
				Client client1 = new Client("TEMPLETON", MONITOR_NAME, MONITOR_PORT, HOST_NAME, 44444, Integer.parseInt(args[0]));
				client1.start();
				Server server1 = new Server("TEMPLETON", MONITOR_PORT, 44444);
				server1.start();
				Client client2 = new Client("SIKORSKI", MONITOR_NAME, MONITOR_PORT, HOST_NAME, 44445, Integer.parseInt(args[1]));
				client2.start();
				Server server2 = new Server("SIKORSKI", MONITOR_PORT, 44445);		
				server2.start();
				Client client3 = new Client("CR89", MONITOR_NAME, MONITOR_PORT, HOST_NAME, 44446, Integer.parseInt(args[2]));
				client3.start();
				Server server3 = new Server("CR89", MONITOR_PORT, 44446);		
				server3.start();
			} catch (Exception e)
			{
			}
		}
	}
}
