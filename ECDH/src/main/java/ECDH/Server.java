package ECDH;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Server {

    private KeyPair serverKeyPair;
    private PrivateKey serverPrivateKey;
    private PublicKey clientPublicKey;

    public Server() {
        try {
            // Generate ECC key pair for the server
            ECDH ecdh = new ECDH();
            serverKeyPair = ecdh.generateECCKeyPair();
            serverPrivateKey = serverKeyPair.getPrivate();

            startServer();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void startServer() {
        try (ServerSocket serverSocket = new ServerSocket(7001)) {
            System.out.println("Server is running...");
            try (Socket clientSocket = serverSocket.accept()) {
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                // Connected with Server
                System.out.println("Client connected: " + clientSocket.getRemoteSocketAddress() + "\n");

                // Start time untuk pertukaran kunci
                long keyExchangeST = System.currentTimeMillis();

                // Send server's public key to the client
                String serverEncodedPublicKey = Base64.getEncoder().encodeToString(serverKeyPair.getPublic().getEncoded());
                out.println(serverEncodedPublicKey);

                // Receive client's public key
                String clientPublicKeyStr = in.readLine();
                byte[] clientPublicKeyBytes = Base64.getDecoder().decode(clientPublicKeyStr);
                clientPublicKey = ECDH.getPublicKeyFromEncoded(clientPublicKeyBytes);

                // Generate shared secret using ECDH
                byte[] sharedSecret = ECDH.generateECDHSharedSecret(serverPrivateKey, clientPublicKey);
                SecretKey symmetricKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
                long keyExchangeET = System.currentTimeMillis();
                long keyExchangeTotal = keyExchangeET - keyExchangeST;
                String encryptedData;
                String ivString;
                while (true) {
                    // Receive encrypted message from client
                    encryptedData = in.readLine();
                    // Start Time
                    long startTime = System.currentTimeMillis();
                    if (encryptedData == null) {
                        break; // Exit loop if client disconnects
                    }
                    ivString = in.readLine();
                    byte[] iv = Base64.getDecoder().decode(ivString);
                    byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
                    System.out.println("Receive encrypted message from client : " + encryptedData);

                    // Decrypt the message
                    String decryptedClientMessage = ECDH.decryptData(symmetricKey, encryptedBytes, iv);
                    System.out.println("Decrypted message from client: " + decryptedClientMessage);

                    // Echo the decrypted message back to client
                    byte[] encryptedResponse = ECDH.encryptData(symmetricKey, decryptedClientMessage, iv);
                    String encodedEncryptedResponse = Base64.getEncoder().encodeToString(encryptedResponse);
                    out.println(encodedEncryptedResponse);
                    out.println(ivString); // Send back the same IV

                    // End Time
                    long endTime = System.currentTimeMillis();
                    long latency = endTime - startTime;
                    out.println(encodedEncryptedResponse);
                    out.println(ivString);
                    System.out.println("Key exchange latency: " + keyExchangeTotal + " ms \n");
                    System.out.println("Latency: " + latency + " ms \n");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        new Server();
    }
}
