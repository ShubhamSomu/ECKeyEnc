import static utility.SimpleUtility.CLIENT_MSG;
import static utility.SimpleUtility.SERVER_MSG;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;

import SecurityModule.Encryptor;
import client.ClientKeyExchange;
import server.ServerKeyExchange;
import utility.SimpleUtility;

public class Driver {
    public static void main(String[] args) throws Exception {
        Encryptor encryptor = new Encryptor();
        KeyPairGenerator keyPairGenerator = encryptor.keyPairGenerator();

        ClientKeyExchange clientKeyExchange = new ClientKeyExchange(keyPairGenerator);
        KeyPair clientKeyPair = clientKeyExchange.generateNewKeyPair();
        Map<String, byte[]> normalisedClientKey = clientKeyExchange.normaliseKeyPair(encryptor, clientKeyPair);

        ServerKeyExchange serverKeyExchange = new ServerKeyExchange(keyPairGenerator);
        KeyPair serverKeyPair = serverKeyExchange.generateNewKeyPair();
        Map<String, byte[]> normalisedServerKey = serverKeyExchange.normaliseKeyPair(encryptor, serverKeyPair);

        // my private key and other guy's public key
        byte[] clientCommonSecret = encryptor.startECDH(normalisedClientKey.get("clientPrivateKey"),
                                                        normalisedServerKey.get("serverPublicKey"));

        byte[] serverCommonSecret = encryptor.startECDH(normalisedServerKey.get("serverPrivateKey"),
                                                        normalisedClientKey.get("clientPublicKey"));

        System.err.println("Client Common Secret :- " + SimpleUtility.bytesToHex(clientCommonSecret));
        System.err.println("Server Common Secret :- " + SimpleUtility.bytesToHex(serverCommonSecret));

        System.err.println("Are secrets equal :- " + Arrays.equals(clientCommonSecret, serverCommonSecret));

        Cipher cipher = encryptor.cipherInit();

        Driver driver = new Driver();
        System.out.println("\n\n");
        driver.doClientToServerComm(encryptor, cipher, serverKeyPair, SimpleUtility.bytesToHex(clientCommonSecret));

        System.out.println("\n\n");

        driver.doServerToClientComm(encryptor, cipher, clientKeyPair);
    }

    // client will send encData by encrypting with server publickey
    public void doClientToServerComm(Encryptor encryptor, Cipher cipher, KeyPair serverKeyPair, String clientCommonSecret) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        // Key clientKey = new SecretKeySpec(clientCommonSecret, 0, clientCommonSecret.length, "DES");
        String encyptedClientData = encryptor.encryptData(cipher, CLIENT_MSG, serverKeyPair.getPublic());

        System.out.println("Client Data:- " + CLIENT_MSG);
        System.out.println("Enc Client Data :- " + encyptedClientData);

        // Key serverKey = new SecretKeySpec(serverCommonSecret, 0, serverCommonSecret.length, "DES");
        String decyptedClientData = encryptor.decryptData(cipher, encyptedClientData, serverKeyPair.getPrivate());
        System.out.println("Dec client data :- " + decyptedClientData);
    }


    // server will send encData by encrypting with clients publickey
    public void doServerToClientComm(Encryptor encryptor, Cipher cipher, KeyPair clientKeyPair) throws
                                                                                                BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        // Key clientKey = new SecretKeySpec(clientCommonSecret, 0, clientCommonSecret.length, "DES");
        String encyptedClientData = encryptor.encryptData(cipher, SERVER_MSG, clientKeyPair.getPublic());

        System.out.println("Client Data:- " + SERVER_MSG);
        System.out.println("Enc Server Data :- " + encyptedClientData);

        // Key serverKey = new SecretKeySpec(serverCommonSecret, 0, serverCommonSecret.length, "DES");
        String decyptedClientData = encryptor.decryptData(cipher, encyptedClientData, clientKeyPair.getPrivate());
        System.out.println("Dec Server data :- " + decyptedClientData);
    }
}
