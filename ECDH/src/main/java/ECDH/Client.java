package ECDH;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Client {

    private KeyPair clientKeyPair;
    private PrivateKey clientPrivateKey;
    private PublicKey serverPublicKey;
    // private static final String SERVER_ADDRESS = "192.168.86.1";
    private static final String SERVER_ADDRESS = "localhost";

    public Client() {
        try {
            // Generate ECC key pair for the client
            ECDH ecdh = new ECDH();
            clientKeyPair = ecdh.generateECCKeyPair();
            clientPrivateKey = clientKeyPair.getPrivate();

            startClient();
        } catch (Exception e) {
            // e.printStackTrace();
        }
    }

    private void startClient() {
        try (Socket clientSocket = new Socket(SERVER_ADDRESS, 7001)) {
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
            // Connected 
            System.out.println("Connected to server: " + clientSocket.getRemoteSocketAddress() + "\n");

            // Receive server's public key
            String serverPublicKeyStr = in.readLine();
            byte[] serverPublicKeyBytes = Base64.getDecoder().decode(serverPublicKeyStr);
            serverPublicKey = ECDH.getPublicKeyFromEncoded(serverPublicKeyBytes);

            // Send client's public key to server
            String clientEncodedPublicKey = Base64.getEncoder().encodeToString(clientKeyPair.getPublic().getEncoded());
            out.println(clientEncodedPublicKey);

            // Generate shared secret using ECDH
            byte[] sharedSecret = ECDH.generateECDHSharedSecret(clientPrivateKey, serverPublicKey);
            SecretKey symmetricKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

            try (Scanner scanner = new Scanner(System.in)) {
                while (true) {
                    // Input message to send to the server
                    System.out.print("Enter message : ");
                    String message = scanner.nextLine();
                    
                    if ("exit".equalsIgnoreCase(message)) {
                        break; // Exit loop if user types "exit"
                    }
                    // Encrypt the message
                    byte[] iv = new byte[16];
                    new java.security.SecureRandom().nextBytes(iv);
                    byte[] encryptedMessage = ECDH.encryptData(symmetricKey, message, iv);

                    // Send encrypted message and IV to server
                    String base64EncryptedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
                    String base64IV = Base64.getEncoder().encodeToString(iv);
                    double startTime = System.nanoTime();
                    out.println(base64EncryptedMessage);
                    out.println(base64IV);
                    

                    // Receive echoed message from server
                    String serverEncryptedResponse = in.readLine();
                    String serverIV = in.readLine();
                    // End Time
                    double endTime = System.nanoTime();

                    byte[] serverEncryptedBytes = Base64.getDecoder().decode(serverEncryptedResponse);
                    String serverDecryptedResponse = ECDH.decryptData(symmetricKey, serverEncryptedBytes, Base64.getDecoder().decode(serverIV));
                    double latency = (endTime - startTime) / 1000000;
                    System.out.println("Response message encrypted from server : " + serverEncryptedResponse);
                    System.out.println("Response message from server: " + serverDecryptedResponse);
                    System.out.println("Latency : " + latency + "ms \n");
                }
            }
            clientSocket.close();
        } catch (Exception e) {
            // e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        new Client();
    }
}
