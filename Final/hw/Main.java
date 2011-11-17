package hw;

public class Main
{
	public static String MONITOR_NAME = "localhost";
	public static int MONITOR_PORT = 8160;
	public static String HOST_NAME = "localhost";

	public static void main(String[] args)
	{
		if (args.length != 2)
		{
			System.out.println("\nbad args");
			System.out.println("usage:java hw3.java IDENT HOST_PORT\n");
		} else
		{
			try
			{
				Client client = new Client(args[0], MONITOR_NAME, MONITOR_PORT, HOST_NAME, Integer.parseInt(args[1]));
				client.start();
				Server server = new Server(args[0], MONITOR_PORT, Integer.parseInt(args[1]));
				server.start();
			} catch (Exception e)
			{
			}
		}
	}
}