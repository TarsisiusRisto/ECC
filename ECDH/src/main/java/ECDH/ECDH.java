package ECDH;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECDH {

    static {
        // Menambahkan BouncyCastle sebagai security provide
        Security.addProvider(new BouncyCastleProvider());
    }

    // Generate kunci ECC (Elliptic Curve Cryptography)
    public KeyPair generateECCKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256); // Menggunakan kurva eliptik 256
        return keyPairGenerator.generateKeyPair();
    }

    public static PublicKey getPublicKeyFromEncoded(byte[] encodedKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
    }

    // Generate shared secret menggunakan ECDH
    public static byte[] generateECDHSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret(); // Shared secret dalam bentuk byte[]
    }

    // Enkripsi data menggunakan AES (simetris)
    public static byte[] encryptData(SecretKey secretKey, String data, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(data.getBytes());
    }

    // Dekripsi data menggunakan AES
    public static String decryptData(SecretKey secretKey, byte[] encryptedData, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return new String(cipher.doFinal(encryptedData));
    }
}
