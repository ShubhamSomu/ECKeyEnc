package ecencryption;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.Security;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.math.ec.ECPoint;

public class ECTwo {
    private Cipher cipher;
    public static final String EC_ALGORITHM = "EC";
    public static final String ECIES_ALGORITHM = "ECIES";
    final protected static char[] hexArray = "0123456789abcdef".toCharArray();
    private static BouncyCastleProvider bcprovider = new BouncyCastleProvider();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static byte[] savePublicKey(PublicKey key) throws Exception {
        //return key.getEncoded();

        ECPublicKey eckey = (ECPublicKey) key;
        return eckey.getQ().getEncoded(true);
    }

    public static PublicKey loadPublicKey(byte[] data) throws Exception {
		/*KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
		return kf.generatePublic(new X509EncodedKeySpec(data));*/

        ECParameterSpec params = ECNamedCurveTable.getParameterSpec("prime192v1");
        ECPublicKeySpec pubKey = new ECPublicKeySpec(
            params.getCurve().decodePoint(data), params);
        KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
        return kf.generatePublic(pubKey);
    }

    public static byte[] savePrivateKey(PrivateKey key) throws Exception {
        //return key.getEncoded();

        ECPrivateKey eckey = (ECPrivateKey) key;
        return eckey.getD().toByteArray();
    }

    public static PrivateKey loadPrivateKey(byte[] data) throws Exception {
        //KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
        //return kf.generatePrivate(new PKCS8EncodedKeySpec(data));

        ECParameterSpec params = ECNamedCurveTable.getParameterSpec("prime192v1");
        ECPrivateKeySpec prvkey = new ECPrivateKeySpec(new BigInteger(data), params);
        KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
        return kf.generatePrivate(prvkey);
    }

    public static void doECDH(String name, byte[] dataPrv, byte[] dataPub) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
        ka.init(loadPrivateKey(dataPrv));
        ka.doPhase(loadPublicKey(dataPub), true);
        byte[] secret = ka.generateSecret();
        System.out.println(name + bytesToHex(secret));
    }

    public static void main(String[] args) throws Exception {
        Cipher cipher =null;
        ECTwo ecTwo = new ECTwo();
        ecTwo.doRunner();
        cipher = ecTwo.cipherInit();
    }

    private Cipher cipherInit() {
        try {
            cipher = Cipher.getInstance(ECIES_ALGORITHM, bcprovider);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return cipher;
    }

/*    public void enc(Cipher cipher , String msg, ) {

    }*/

    private void doRunner() throws Exception {
        Security.addProvider(bcprovider);

        KeyPairGenerator kpgen = KeyPairGenerator.getInstance("ECDH", "BC");
        kpgen.initialize(new ECGenParameterSpec("prime192v1"), new SecureRandom());
        KeyPair pairA = kpgen.generateKeyPair();
        KeyPair pairB = kpgen.generateKeyPair();
        System.out.println("Alice: " + pairA.getPrivate());
        System.out.println("Alice: " + pairA.getPublic());
        System.out.println("Bob:   " + pairB.getPrivate());
        System.out.println("Bob:   " + pairB.getPublic());
        byte[] dataPrvA = savePrivateKey(pairA.getPrivate());
        byte[] dataPubA = savePublicKey(pairA.getPublic());
        byte[] dataPrvB = savePrivateKey(pairB.getPrivate());
        byte[] dataPubB = savePublicKey(pairB.getPublic());
        System.out.println("Alice Prv: " + bytesToHex(dataPrvA));
        System.out.println("Alice Pub: " + bytesToHex(dataPubA));
        System.out.println("Bob Prv:   " + bytesToHex(dataPrvB));
        System.out.println("Bob Pub:   " + bytesToHex(dataPubB));

        doECDH("Alice's secret: ", dataPrvA, dataPubB);
        doECDH("Bob's secret:   ", dataPrvB, dataPubA);
    }
}
