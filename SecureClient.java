import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.io.*;
import java.util.*;

/**
 * Programming Assignment 2
 * Encryption and Security
 * 
 * @author Asuman Aydın & Muhammad Bin Sanaullah
 * @version 1.0
 * @since 2020-04-7
 */

public class SecureClient {

	// functionalities used in communication btw client and server
	private static PrintWriter writer = null;
	private static BufferedReader fromServer = null;
	private static InputStream inputStream = null;
	private static InputStreamReader inputStreamRe = null;
	private static Socket socketClient = null;
	private static Scanner in = null;

	// Authentication
	private static Boolean userAuth = false;
	private static Boolean passAuth = false;

	// Version of the file
	int version;

	/**
	 * This is the main method
	 * 
	 * @param args used to take localhost and port
	 * @return Nothing.
	 * @exception IOException On input errors.
	 * @see IOException
	 */
	public static void main(String args[]) throws IOException {

		SecureClient myObje = new SecureClient();
		myObje.version = 0;
		String ipaddress = args[0]; // = "localhost";
		int port = Integer.parseInt(args[1]);// = 60000;

		// Connect to the server
		socketClient = new Socket(ipaddress, port);
		System.out.println("Connection is started.");

		// to take the input from client
		inputStream = socketClient.getInputStream();
		inputStreamRe = new InputStreamReader(inputStream);
		fromServer = new BufferedReader(inputStreamRe);
		writer = new PrintWriter(socketClient.getOutputStream(), true);
		in = new Scanner(System.in);

		// USER AUTH
		System.out.print("Username Command:");
		String userName = in.nextLine();
		if (userName.contains("EXIT")) {
			try {
				writer.close();
				fromServer.close();
				inputStream.close();
				inputStreamRe.close();
				socketClient.close();
				in.close();
			} catch (IOException exc) {
				System.out.println("Exception while exiting: " + exc.getMessage());
			}
			System.out.println("Connection is closed.");
			System.exit(0);
		}
		userAuth = sendUserCommand(userName);
		if (userAuth == false) {
			try {
				writer.close();
				fromServer.close();
				inputStream.close();
				inputStreamRe.close();
				socketClient.close();
				in.close();
			} catch (IOException exc) {
				System.out.println("Exception while exiting: " + exc.getMessage());
			}
			System.out.println("Connection is closed.");
			System.exit(0);
		}
		// PASS AUTH
		System.out.print("Password Command:");
		String password = in.nextLine();
		if (password.contains("EXIT")) {
			try {
				writer.close();
				fromServer.close();
				inputStream.close();
				inputStreamRe.close();
				socketClient.close();
				in.close();
			} catch (IOException exc) {
				System.out.println("Exception while exiting: " + exc.getMessage());
			}
			System.out.println("Connection is closed.");
			System.exit(0);
		}
		passAuth = sendPassCommand(password);
		if (passAuth == false) {
			try {
				writer.close();
				fromServer.close();
				inputStream.close();
				inputStreamRe.close();
				socketClient.close();
				in.close();
			} catch (IOException exc) {
				System.out.println("Exception while exiting: " + exc.getMessage());
			}
			System.out.println("Connection is closed.");
			System.exit(0);
		}
		String[] response = { "OK", "INVALID" };
		System.out.println("Please enter a command to execute: ");
		String command = in.nextLine();
		if (command.contains("EXIT")) {
			try {
				writer.close();
				fromServer.close();
				inputStream.close();
				inputStreamRe.close();
				socketClient.close();
				in.close();
			} catch (IOException exc) {
				System.out.println("Exception while exiting: " + exc.getMessage());
			}
			System.out.println("Connection is closed.");
			System.exit(0);
		}
		while (!command.contains("EXIT")) {
			// UPDATE
			if (command.contains("UPDT")) {
				writer.println(command);
				String responseFromServer = null;
				try {
					responseFromServer = fromServer.readLine();
					System.out.println(responseFromServer);
				} catch (IOException exc) {
					System.out.println("about update: " + exc.getMessage());
				}
				if (responseFromServer.contains(response[0]) && !responseFromServer.contains(response[1])) {
					int versionCurrent = myObje.getVersionOfClient();
					versionCurrent++;
					myObje.setVersionOfClient(versionCurrent);
				} else {
					System.out.println("The other functions can be used.");
				}
			}
			// WRITE
			else if (command.contains("WRTE")) {
				writer.println(command);
				String responseFromServerWrite = null;
				try {
					responseFromServerWrite = fromServer.readLine();
					System.out.println(responseFromServerWrite);
				} catch (IOException exc) {
					System.out.println("About write command: " + exc.getMessage());
				}
			}
			// APPEND
			else if (command.contains("APND")) {
				writer.println(command);
				String responseFromServerapn = null;
				try {
					responseFromServerapn = fromServer.readLine();
					System.out.println(responseFromServerapn);
				} catch (IOException exc) {
					System.out.println("About append: " + exc.getMessage());
				}
			}
			System.out.println("Please enter a command to execute: ");
			command = in.nextLine();
		}
		// CLOSING OF THE PROGRAM
		try {
			writer.close();
			fromServer.close();
			inputStream.close();
			inputStreamRe.close();
			socketClient.close();
			in.close();
		} catch (IOException exc) {
			System.out.println("Exception while exiting: " + exc.getMessage());
		}
		System.out.println("Connection is closed.");
		System.exit(0);
	}

	/**
	 * This method is used to send USER command with username and get the response
	 * from the server
	 * 
	 * @param String username numA This is the first parameter
	 * @return boolean if the username is OK or INVALID
	 */
	public static boolean sendUserCommand(String usernameClient) {
		writer.println(usernameClient);
		String[] response = { "OK", "INVALID" };
		try {
			String responseFromServer = fromServer.readLine();
			System.out.println(responseFromServer);
			return responseFromServer.contains(response[0]) && !responseFromServer.contains(response[1]);
		} catch (IOException exc) {
			System.out.println("About Username:" + exc.getMessage());
		}
		return false;
	}

	/**
	 * This method is used to send PASS command with password and get the response
	 * from the server
	 * 
	 * @param String password This is the first parameter
	 * @return boolean if the password is OK or INVALID
	 */
	public static boolean sendPassCommand(String passwordClient) {
		writer.println(passwordClient);
		String[] response = { "OK", "INVALID" };
		try {
			String responseFromServer = fromServer.readLine();
			System.out.println(responseFromServer);
			return responseFromServer.contains(response[0]) && !responseFromServer.contains(response[1]);
		} catch (IOException exc) {
			System.out.println("About Password:" + exc.getMessage());
		}
		return false;
	}

	// KEEPING THE VERSION, JUST IN CASE
	public int getVersionOfClient() {
		return this.version;
	}

	public void setVersionOfClient(int versionCurrent) {
		this.version = versionCurrent;
	}
}
