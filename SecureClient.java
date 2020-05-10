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
 * @author Asuman Ayd?n & Muhammad Bin Sanaullah
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

  
  CryptoHelper crypto = new CryptoHelper();
  
  while(true) {
    
   int p = Integer.parseInt(args[0]);
   socketClient = new Socket("127.0.0.1", p);
   inputStream = socketClient.getInputStream();
   baos = new ByteArrayOutputStream();
   out =  socketClient.getOutputStream();
   System.out.println("Connection is started.");

   sendHELLO();

   byte[] cert = receiveHELLO();

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
  String s = new String(data,StandardCharsets.US_ASCII);//decoding needs to specific to US-ASCII
  return s;
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
    try {
    byte[] header = new byte[8];
    byte[] length = new byte[4];
    inputStream.read(header);
    String header = decodeUS_ASCII(header);
    if(header.contains("HELLO"))
    {
      inputStream.read(length);
      int lengthx = byteArrayToInt(length);
      byte[] data = new byte[length];
      inputStream.read(data);
    }

   return data;
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
   String cert_s = decodeUS_ASCII(cert);
    cert_s = cert_s.substring(cert_s.indexOf("PK=") + 3);
    cert_s = cert_s.substring(0, cert_s.indexOf("C"));
    byte[] pk = cert_s.getBytes(StandardCharsets.US_ASCII);
    return pk;
  }

 private static String getCA(byte[] cert) throws IOException  {
  String cert_s = decodeUS_ASCII(cert);
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
    byte[] header = new byte[8];
    byte[] length = new byte[4];
    inputStream.read(header);
    String header = decodeUS_ASCII(header);
    if(header.contains("HELLO"))
    {
      inputStream.read(length);
      int lengthx = byteArrayToInt(length);
      byte[] data = new byte[length];
      inputStream.read(data);
    }
   return data;
  }
  catch(IOException exc)
  {
   System.out.println("About Handshake" + exc.getMessage());
   return null;
  }
  //return null;
 }

 private static void sendHELLO() throws IOException {
  
  String hello = "HELLOxxx";
  byte[] helloByte = hello.getBytes(StandardCharsets.US_ASCII);
  out.write(helloByte);
 }
}
//change the names etc
public static int byteArrayToInt(byte[] b) 
{
    return   b[3] & 0xFF |
            (b[2] & 0xFF) << 8 |
            (b[1] & 0xFF) << 16 |
            (b[0] & 0xFF) << 24;
}
