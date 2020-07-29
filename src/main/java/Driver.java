import static utility.SimpleUtility.CLIENT_MSG;
import static utility.SimpleUtility.SERVER_MSG;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import SecurityModule.Encryptor;
import client.ClientKeyExchange;
import intruder.IntruderKeyExchange;
import server.ServerKeyExchange;
import utility.SimpleUtility;

public class Driver {
    public static void main(String[] args) throws Exception {
        Driver driver = new Driver();
        Encryptor encryptor = new Encryptor();

        Cipher cipher = encryptor.cipherInit();

        KeyPairGenerator keyPairGenerator = encryptor.keyPairGenerator();

        ClientKeyExchange clientKeyExchange = new ClientKeyExchange(keyPairGenerator);
        KeyPair clientKeyPair = clientKeyExchange.generateNewKeyPair();
        Map<String, byte[]> normalisedClientKey = clientKeyExchange.normaliseKeyPair(encryptor, clientKeyPair);

        ServerKeyExchange serverKeyExchange = new ServerKeyExchange(keyPairGenerator);
        KeyPair serverKeyPair = serverKeyExchange.generateNewKeyPair();
        Map<String, byte[]> normalisedServerKey = serverKeyExchange.normaliseKeyPair(encryptor, serverKeyPair);

        IntruderKeyExchange intruderKeyExchange = new IntruderKeyExchange(keyPairGenerator);
        KeyPair intruderKeyPair = intruderKeyExchange.generateNewKeyPair();
        Map<String, byte[]> normalisedIntruderKey = intruderKeyExchange.normaliseKeyPair(encryptor, intruderKeyPair);

        // my private key and other guy's public key
        byte[] clientCommonSecret = encryptor.startECDH(normalisedClientKey.get("clientPrivateKey"),
                                                        normalisedServerKey.get("serverPublicKey"));

        byte[] serverCommonSecret = encryptor.startECDH(normalisedServerKey.get("serverPrivateKey"),
                                                        normalisedClientKey.get("clientPublicKey"));

        System.err.println("Client Common Secret :- " + SimpleUtility.bytesToHex(clientCommonSecret));
        System.err.println("Server Common Secret :- " + SimpleUtility.bytesToHex(serverCommonSecret));

        System.err.println("Are secrets equal :- " + Arrays.equals(clientCommonSecret, serverCommonSecret));

        System.out.println("\n\n");
        driver.doClientToServerComm(encryptor, cipher, serverKeyPair,  clientCommonSecret, serverCommonSecret);

        System.out.println("\n\n");

/*        driver.doServerToClientComm(encryptor, cipher, clientKeyPair);

        driver.intruderTest(clientKeyPair, intruderKeyPair, encryptor, cipher, intruderKeyExchange, clientKeyExchange);*/
    }

    // client will send encData by encrypting with server publickey
    public void doClientToServerComm(Encryptor encryptor, Cipher cipher, KeyPair serverKeyPair, byte[] clientCommonSecret, byte[] serverCommonSecret)
        throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException {
        // Key clientKey = new SecretKeySpec(clientCommonSecret, 0, clientCommonSecret.length, "DES");
        String encyptedClientData = encryptor.encryptData(cipher, CLIENT_MSG, serverKeyPair.getPublic(), SimpleUtility.bytesToHex(clientCommonSecret));

        System.out.println("Client Data:- " + CLIENT_MSG);
        System.out.println("Enc Client Data :- " + encyptedClientData);

        // Key serverKey = new SecretKeySpec(serverCommonSecret, 0, serverCommonSecret.length, "DES");
        String decyptedClientData = encryptor.decryptData(cipher, encyptedClientData, serverKeyPair.getPrivate(), SimpleUtility.bytesToHex(serverCommonSecret));
        System.out.println("Dec client data :- " + decyptedClientData);
    }
/*
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

    // suppose intruder intercepted client -> server comm. and sent intruder pub key to client while capturing client's pub key
    // this method is called at client, now client has intruder's pub key rather than server's
    public void intruderTest(KeyPair clientKeyPair, KeyPair intruderKeyPair, Encryptor encryptor, Cipher cipher,
                             IntruderKeyExchange intruderKeyExchange, ClientKeyExchange clientKeyExchange) throws Exception {
        System.out.println("\n\n \t\t -- Intruder Test --- \t\t\n");

        Map<String, byte[]> normalisedIntruderKeyMap = intruderKeyExchange.normaliseKeyPair(encryptor, clientKeyPair);
        Map<String, byte[]> normalisedClientKeyMap = clientKeyExchange.normaliseKeyPair(encryptor, intruderKeyPair);

        byte[] clientCommonSecret = encryptor.startECDH(normalisedClientKeyMap.get("clientPrivateKey"),
                                                        normalisedIntruderKeyMap.get("intruderPublicKey"));
        byte[] intruderCommonSecret = encryptor.startECDH(normalisedIntruderKeyMap.get("intruderPrivateKey"),
                                                          normalisedClientKeyMap.get("clientPublicKey"));

        System.out.println("Hacked Client common secret :- " + SimpleUtility.bytesToHex(clientCommonSecret));
        System.out.println("Intruder common secret :- " + SimpleUtility.bytesToHex(intruderCommonSecret));
        System.out.println("Are keys equal? :- " + Arrays.equals(clientCommonSecret, intruderCommonSecret));
        // here server is intruder
        doClientToServerComm(encryptor, cipher, intruderKeyPair);

        System.out.println("\n \t\t --- Intruder Test ENDS ---\t\t\n");
    }*/
}
