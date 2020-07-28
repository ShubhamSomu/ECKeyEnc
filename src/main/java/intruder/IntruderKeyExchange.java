package intruder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.HashMap;
import java.util.Map;

import SecurityModule.Encryptor;

public class IntruderKeyExchange {
        private final KeyPairGenerator keyPairGenerator;

        public IntruderKeyExchange(KeyPairGenerator keyPairGenerator) {
            this.keyPairGenerator = keyPairGenerator;
        }

        public KeyPair generateNewKeyPair(){
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            return keyPair;
        }

        public Map<String,byte[]> normaliseKeyPair(Encryptor encryptor, KeyPair keyPair) throws Exception {
            Map<String,byte[]> normalisedServerKeyMap = new HashMap<String, byte[]>();
            byte[] normalisedPrivateKey = encryptor.normalisePrivateKey(keyPair.getPrivate());
            byte[] normalisedPublicKey = encryptor.normalisePublicKey(keyPair.getPublic());

            normalisedServerKeyMap.put("serverPrivateKey", normalisedPrivateKey);
            normalisedServerKeyMap.put("serverPublicKey", normalisedPublicKey);
            return normalisedServerKeyMap;
        }
}
