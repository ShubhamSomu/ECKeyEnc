package client;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.HashMap;
import java.util.Map;

import SecurityModule.Encryptor;

public class ClientKeyExchange {
    private final KeyPairGenerator keyPairGenerator;

    public ClientKeyExchange(KeyPairGenerator keyPairGenerator) {
        this.keyPairGenerator = keyPairGenerator;
    }

    public KeyPair generateNewKeyPair(){
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public Map<String,byte[]> normaliseKeyPair(Encryptor encryptor,KeyPair keyPair) throws Exception {
        Map<String,byte[]> normalisedClientKeyMap = new HashMap<String, byte[]>();
        byte[] normalisedPrivateKey = encryptor.normalisePrivateKey(keyPair.getPrivate());
        byte[] normalisedPublicKey = encryptor.normalisePublicKey(keyPair.getPublic());

        normalisedClientKeyMap.put("clientPrivateKey", normalisedPrivateKey);
        normalisedClientKeyMap.put("clientPublicKey", normalisedPublicKey);
        return normalisedClientKeyMap;
    }
}
