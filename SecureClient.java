import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.lang.Object;

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
		int port = Integer.parseInt(args[0]);

		// to take the input from client
		inputStream = socketClient.getInputStream();
		inputStreamRe = new InputStreamReader(inputStream);
		fromServer = new BufferedReader(inputStreamRe);
		writer = new PrintWriter(socketClient.getOutputStream(), true);
		in = new Scanner(System.in);

		CryptoHelper crypto = new CryptoHelper();


		while(true) {

			socketClient = new Socket("127.0.0.1", port);
			System.out.println("Connection is started.");
			// --- HANDSHAKE START
			sendHELLO();

			// Receive the certificate
			byte[] cert = receiveHELLO();

			// Get necessary fields from the certificate
			byte[] signature = getSignature(cert);
			String ca = getCA(cert);
			byte[] serverPublicKey = getPK(cert);

			// Verification is successful:
			if (crypto.verifySignature(cert, signature, ca)) 
				break;

			// Verification fails:
			else 
				socketClient.close();
		}

		// Create and send encrypted secret
		int secret = crypto.generateSecret();
		byte[] secretEncrypted = crypto.encryptSecretAsymmetric(secret, serverPublicKey);
		sendSECRET(secretEncrypted);
		// --- HANDSHAKE END


		// --- AUTHENTICATION START
		sendSTARTENC();  // Start encryption

		// Send encrypted authentication info
		byte[] authEncrypted = crypto.encryptSymmetric("bilkent cs421", secret);
		sendAUTH(authEncrypted);

		// Receive authentication response
		byte[] data = receiveRESPONSE();
		String response = crypto.decryptSymmetric(data, secret);
		print(response);  // This should be "OK"

		sendSTARTENC();  // End encryption
		// --- AUTHENTICATION END
		// --- VIEW PUBLIC POSTS START
		sendPUBLIC();
		byte[] data = receiveRESPONSE();

		// Decode the byte array into a string & display
		String response = decodeUS_ASCII(data);
		print(response);
		// --- VIEW PUBLIC POSTS END


		// --- VIEW PRIVATE MESSAGES START
		sendSTARTENC();  // Start encryption
		sendPRIVATE();

		// Receive, decrypt & display
		byte[] data = receiveRESPONSE();
		String response = crypto.decryptSymmetric(data, secret);
		print(response);

		sendSTARTENC();  // End encryption
		// --- VIEW PRIVATE MESSAGES END


		// LOGOUT
		sendLOGOUT();
		socketClient.close();

	}

	private static void sendLOGOUT() {
		// TODO Auto-generated method stub

	}

	private static void sendPRIVATE() {
		// TODO Auto-generated method stub

	}

	private static String decodeUS_ASCII(byte[] data) {
		// TODO Auto-generated method stub
		return null;
	}

	private static void sendPUBLIC() {
		// TODO Auto-generated method stub

	}

	private static void print(String response) {
		// TODO Auto-generated method stub

	}

	private static byte[] receiveRESPONSE() {
		// TODO Auto-generated method stub
		return null;
	}

	private static void sendAUTH(byte[] authEncrypted) {
		// TODO Auto-generated method stub

	}

	private static void sendSTARTENC() {
		// TODO Auto-generated method stub

	}

	private static void sendSECRET(byte[] secretEncrypted) {
		// TODO Auto-generated method stub

	}

	private static byte[] getPK(byte[] cert) {
		// TODO Auto-generated method stub
		return null;
	}

	private static String getCA(byte[] cert) {
		// TODO Auto-generated method stub
		return null;
	}

	private static byte[] getSignature(byte[] cert) {
		// TODO Auto-generated method stub
		return null;
	}

	private static byte[] receiveHELLO() {
		// TODO Auto-generated method stub
		return null;
	}

	private static void sendHELLO() {
		// TODO Auto-generated method stub

	}
}
