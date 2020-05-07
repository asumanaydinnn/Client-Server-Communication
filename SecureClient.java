import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
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

	private static InputStream inputStream = null;
	private static ByteArrayOutputStream baos = null;
	private static Socket socketClient = null;
	static byte[] serverPublicKeys;
    static OutputStream out = null;


	/**
	 * This is the main method
	 * 
	 * @param args used to take localhost and port
	 * @return Nothing.
	 * @exception IOException On input errors.
	 * @see IOException
	 */
	public static void main(String args[]) throws IOException {

		int port = Integer.parseInt(args[0]);

		CryptoHelper crypto = new CryptoHelper();
		inputStream = socketClient.getInputStream();
		baos = new ByteArrayOutputStream();
		out =  socketClient.getOutputStream();

		
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
			byte[] serverPublicKeys  = getPK(cert);

			// Verification is successful:
			if (crypto.verifySignature(cert, signature, ca)) 
			{
				System.out.println("success");
				break;
			}
			// Verification fails:
			else 
			{
				System.out.println("fail");
				socketClient.close();
			}
		}
		
		// Create and send encrypted secret
		int secret = crypto.generateSecret();
		byte[] secretEncrypted = crypto.encryptSecretAsymmetric(secret, serverPublicKeys);
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
		byte[] dataResponse = receiveRESPONSE();

		// Decode the byte array into a string & display
		String responseData = decodeUS_ASCII(dataResponse);
		print(responseData);
		// --- VIEW PUBLIC POSTS END


		// --- VIEW PRIVATE MESSAGES START
		sendSTARTENC();  // Start encryption
		sendPRIVATE();

		// Receive, decrypt & display
		byte[] data3 = receiveRESPONSE();
		String response3 = crypto.decryptSymmetric(data3, secret);
		print(response3);

		sendSTARTENC();  // End encryption
		// --- VIEW PRIVATE MESSAGES END


		// LOGOUT
		sendLOGOUT();
		socketClient.close();

	}

	private static void sendLOGOUT() throws IOException {
		// TODO Auto-generated method stub
		String logout = "LOGOUT";
		byte[] logoutByte = logout.getBytes(StandardCharsets.US_ASCII);
		out.write(logoutByte);
	}

	private static void sendPRIVATE() throws IOException {
		// TODO Auto-generated method stub
		String privateT = "PRIVATE";
		byte[] privateByte = privateT.getBytes(StandardCharsets.US_ASCII);
		out.write(privateByte);
	}

	private static String decodeUS_ASCII(byte[] data) {
		// TODO Auto-generated method stub
		return null;
	}

	private static void sendPUBLIC() throws IOException {
		String publicT = "PUBLIC";
		byte[] publicByte = publicT.getBytes(StandardCharsets.US_ASCII);
		out.write(publicByte);
	}

	private static void print(String response) {
		// TODO Auto-generated method stub
		System.out.println("Response:" + response);
	}

	private static byte[] receiveRESPONSE() {
		// TODO Auto-generated method stub
		return null;
	}

	private static void sendAUTH(byte[] authEncrypted) throws IOException {
		// TODO Auto-generated method stub
		out.write(authEncrypted);
	}

	private static void sendSTARTENC() throws IOException {
		// TODO Auto-generated method stub
		String start = "STARTENC";
		byte[] startByte = start.getBytes(StandardCharsets.US_ASCII);
		out.write(startByte);
	}

	private static void sendSECRET(byte[] secretEncrypted) throws IOException  {
		out.write(secretEncrypted);
	}

	private static byte[] getPK(byte[] cert) throws IOException {
		 String cert_s = new String(cert);
		  cert_s = cert_s.substring(cert_s.indexOf("PK=") + 3);
		  cert_s = cert_s.substring(0, cert_s.indexOf("C"));
		  byte[] pk = cert_s.getBytes(StandardCharsets.US_ASCII);
		  return pk;
		}

	private static String getCA(byte[] cert) throws IOException  {
		String cert_s = new String(cert);
		  cert_s = cert_s.substring(cert_s.indexOf("CA=") + 3);
		  cert_s = cert_s.substring(0, cert_s.indexOf("S"));
		  return cert_s;
	}

	private static byte[] getSignature(byte[] cert) throws IOException 
	{
		byte[] signature =  Arrays.copyOfRange(cert, cert.length-8,cert.length);
		return signature;
	}

	private static byte[] receiveHELLO() {
		
		try {
			byte responseFromServer[] = new byte[1024];
			baos.write(responseFromServer,0, inputStream.read(responseFromServer));
			byte cert[] = baos.toByteArray();
			System.out.println(responseFromServer);
			return cert;
		}
		catch(IOException exc)
		{
			System.out.println("About Handshake" + exc.getMessage());
		}
		return null;
	}

	private static void sendHELLO() throws IOException {
		
		String hello = "HELLO";
		byte[] helloByte = hello.getBytes(StandardCharsets.US_ASCII);
		out.write(helloByte);
	}
}
