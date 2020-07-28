package SecurityModule;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

import utility.SimpleUtility;

public class Encryptor {

    private Cipher cipher;
    public static final String EC_ALGORITHM = "EC";
    public static final String ECIES_ALGORITHM = "ECIES";

    private static BouncyCastleProvider bcprovider = new BouncyCastleProvider();

    public KeyPairGenerator keyPairGenerator() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        Security.addProvider(bcprovider);

        KeyPairGenerator kpgen = KeyPairGenerator.getInstance("ECDH", "BC");
        kpgen.initialize(new ECGenParameterSpec("prime192v1"), new SecureRandom());
        return kpgen;
    }

    public byte[] normalisePrivateKey(PrivateKey key) throws Exception {
        //return key.getEncoded();

        ECPrivateKey eckey = (ECPrivateKey) key;
        return eckey.getD().toByteArray();
    }

    public byte[] normalisePublicKey(PublicKey key) throws Exception {
        //return key.getEncoded();

        ECPublicKey eckey = (ECPublicKey) key;
        return eckey.getQ().getEncoded(true);
    }

    public static PrivateKey loadPrivateKey(byte[] data) throws Exception {
        ECParameterSpec params = ECNamedCurveTable.getParameterSpec("prime192v1");
        ECPrivateKeySpec prvkey = new ECPrivateKeySpec(new BigInteger(data), params);
        KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
        return kf.generatePrivate(prvkey);
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

    public byte[] startECDH(byte[] dataPrv, byte[] dataPub) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
        ka.init(loadPrivateKey(dataPrv));
        ka.doPhase(loadPublicKey(dataPub), true);
        byte[] secret = ka.generateSecret();
        return secret;
    }

    public Cipher cipherInit() {
        try {
            cipher = Cipher.getInstance(ECIES_ALGORITHM, bcprovider);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return cipher;
    }

    public String encryptData(Cipher cipher, String msg, PublicKey publicKey) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] plainTextBytes = msg.getBytes();

        cipher.init(Cipher.ENCRYPT_MODE, publicKey, new SecureRandom());
        byte[] cipherText = cipher.doFinal(plainTextBytes);
        String base64EncText = Base64.getEncoder().encodeToString(cipherText);
        return base64EncText;
    }

    public String decryptData(Cipher cipher, String base64EncText, PrivateKey privateKey) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] cipherText = Base64.getDecoder().decode(base64EncText);
        cipher.init(Cipher.DECRYPT_MODE, privateKey, new SecureRandom());
        String plainText = new String(cipher.doFinal(cipherText));
        return plainText;
    }
}
