import io.github.novacrypto.bip39.MnemonicGenerator;
import io.github.novacrypto.bip39.wordlists.English;
import org.bitcoinj.core.Base58;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.crypto.*;
import org.bitcoinj.params.MainNetParams;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import static io.github.novacrypto.hashing.Sha256.sha256;


public class ECUtils {
    public static final String SIGN_ALGORITHM = "SHA256withECDSA";
    public static final String ECDSA = "ECDSA";
    public static final String PRIME_256V1 = "prime256v1";
    public static final String ALGORITHM = "EC";
    public static final String SPACE_NAME = "prime256v1";// eq prime256v1

    private static PublicKey getPublicKeyFromBytes(byte[] pubKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(PRIME_256V1);
        KeyFactory kf = KeyFactory.getInstance(ECDSA, new BouncyCastleProvider());
        ECNamedCurveSpec params = new ECNamedCurveSpec(PRIME_256V1, spec.getCurve(), spec.getG(), spec.getN());
        ECPoint point = ECPointUtil.decodePoint(params.getCurve(), pubKey);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
        ECPublicKey pk = (ECPublicKey) kf.generatePublic(pubKeySpec);
        return pk;
    }
    private static ECPublicKey getPulicKeyFromAddress(String address) {
        String flag = address.substring(0, 3);
        if (!flag.equals("OSN")) {
            System.out.println("error osn id");
            return null;
        }
        // decode base58
        String base58str = address.substring(3);
        //Base58 base58 = new Base58();
        try {
            byte[] data = Base58.decode(base58str);
            byte[] pub = null;
            if (data.length >= 67 && data[2] == 4) {
                pub = new byte[65];
                System.arraycopy(data, 2, pub, 0, 65);
            }
            if (pub != null) {
                // 转化成公钥
                return getPublicKeyFromHex(pub);
            }
        } catch (Exception e) {
            LogFile.logInfo("getPulicKeyFromAddress: "+e.getMessage());
            return null;
        }
        return null;
    }
    private static ECPublicKey getPublicKeyFromHex(byte[] pubKey) {
        ECPublicKey pk;
        try {
            Provider provider = new BouncyCastleProvider();
            org.bouncycastle.jce.spec.ECNamedCurveParameterSpec spec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec(SPACE_NAME);
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM, provider);
            org.bouncycastle.jce.spec.ECNamedCurveSpec params = new org.bouncycastle.jce.spec.ECNamedCurveSpec(SPACE_NAME, spec.getCurve(), spec.getG(), spec.getN());
            ECPoint point = org.bouncycastle.jce.ECPointUtil.decodePoint(params.getCurve(), pubKey);
            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
            pk = (ECPublicKey) kf.generatePublic(pubKeySpec);
            return pk;
        } catch (Exception e) {
            LogFile.logInfo("getPublicKeyFromHex: "+e.getMessage());
        }
        return null;
    }
    private static ECPublicKey getPublicKeyFromPrivateKey(ECPrivateKey privateKey) {
        try {
            Provider provider = new BouncyCastleProvider();
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM, provider);
            org.bouncycastle.jce.spec.ECParameterSpec ecSpec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec(SPACE_NAME);
            org.bouncycastle.math.ec.ECPoint Q = ecSpec.getG().multiply(((org.bouncycastle.jce.interfaces.ECPrivateKey) privateKey).getD());
            org.bouncycastle.jce.spec.ECPublicKeySpec pubSpec = new org.bouncycastle.jce.spec.ECPublicKeySpec(Q, ecSpec);
            ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(pubSpec);
            return publicKey;
        } catch (Exception e) {
            LogFile.logInfo("getPublicKeyFromPrivateKey: "+e.getMessage());
        }
        return null;
    }
    private static ECPrivateKey getEcPrivateKeyFromHex(String priKey){
        try {
            Provider provider = new BouncyCastleProvider();
            org.bouncycastle.jce.spec.ECNamedCurveParameterSpec spec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec(SPACE_NAME);
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM, provider);
            org.bouncycastle.jce.spec.ECNamedCurveSpec params = new org.bouncycastle.jce.spec.ECNamedCurveSpec(SPACE_NAME, spec.getCurve(), spec.getG(), spec.getN());
            BigInteger s = new BigInteger(priKey, 16);
            ECPrivateKeySpec keySpec =new ECPrivateKeySpec(s, params);
            ECPrivateKey pk = (ECPrivateKey)kf.generatePrivate(keySpec);
            return pk;
        } catch (Exception e) {
            LogFile.logInfo("getEcPrivateKeyFromHex: "+e.getMessage());
        }
        return null;
    }

    public static boolean verifySign(String osnID, String origData, String signData){
        try {
            ECPublicKey pkey = ECUtils.getPulicKeyFromAddress(osnID);
            //byte[] data = Base58.decode(origData);
            byte[] sign = Base58.decode(signData);
            Signature ecdsaVerify = Signature.getInstance(SIGN_ALGORITHM, new BouncyCastleProvider());
            ecdsaVerify.initVerify(pkey);
            ecdsaVerify.update(origData.getBytes());
            return ecdsaVerify.verify(sign);
        }
        catch (Exception e){
            LogFile.logInfo("verifySign:" + e.getMessage());
        }
        return false;
    }

    public static byte[] ECDecrypt(String priKey, String data){
        ECPrivateKey privateKey = getEcPrivateKeyFromHex(priKey);
        return ECDecrypt(privateKey, data);
    }
    private static byte[] ECDecrypt(ECPrivateKey privateKey, String data){
        try {
            byte[] rawData = Base58.decode(data);
            short keyLength = (short)((rawData[0]&0xff)|((rawData[1]&0xff)>>8));
            byte[] ecData = new byte[keyLength];
            System.arraycopy(rawData,2,ecData,0,keyLength);
            ecData = ECIESDecrypt(privateKey, ecData);

            byte[] aesKey = new byte[16];
            byte[] aesIV = new byte[16];
            byte[] aesData = new byte[rawData.length-keyLength-2];
            System.arraycopy(ecData,0,aesKey,0,16);
            System.arraycopy(ecData,16,aesIV,0,16);
            System.arraycopy(rawData,keyLength+2,aesData,0,rawData.length-keyLength-2);

            IvParameterSpec iv = new IvParameterSpec(aesIV);
            SecretKeySpec key = new SecretKeySpec(aesKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            byte[] decData = cipher.doFinal(aesData);
            return decData;
            //return new String(decData);
        }catch (Exception e){
            LogFile.logInfo("ECDecrypt: "+e.getMessage());
        }
        return null;
    }
    private static byte[] ECIESEncrypt(ECPublicKey pubkey, byte[] raw){
        try {
            Cipher cipher = Cipher.getInstance("ECIESwithAES/NONE/PKCS7Padding",new BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE, pubkey);
            byte[] cipherText = cipher.doFinal(raw);
            return cipherText;
        } catch (Exception e){
            LogFile.logInfo("ECIESEncrypt: "+e.getMessage());
            return null;
        }
    }
    private static byte[] ECIESDecrypt(ECPrivateKey privateKey, byte[] raw){
        try {
            //Cipher cipher = Cipher.getInstance("ECIESwithAES/NONE/PKCS7Padding",new BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance("ECIES",new BouncyCastleProvider());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] cipherText = cipher.doFinal(raw);
            return cipherText;
        } catch (Exception e){
            LogFile.logInfo("ECIESDecrypt: "+e.getMessage());
            return null;
        }
    }

    private static String createMnemonic(){
        StringBuilder sb = new StringBuilder();
        byte[] entropy = new byte[20];
        new SecureRandom().nextBytes(entropy);
        new MnemonicGenerator(English.INSTANCE).createMnemonic(entropy, sb::append);
        String mnemonics = sb.toString();
        return mnemonics;
    }
    private static String bytesToHex(byte[] bytes) {
        StringBuffer sb = new StringBuffer();
        for(int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if(hex.length() < 2){
                sb.append(0);
            }
            sb.append(hex);
        }
        return sb.toString();
    }
    private static String GenSubPrivateKey(String mnemonic, ChildNumber[] path){
        byte[] seed = MnemonicCode.toSeed(Arrays.asList(mnemonic.split(" ")), "");
        //byte[] seed = MnemonicUtils.generateSeed(mnemonic, null);
        DeterministicKey masterPrivateKey = HDKeyDerivation.createMasterPrivateKey(seed);
        NetworkParameters MAINNET = MainNetParams.get();

        DeterministicHierarchy dh = new DeterministicHierarchy(masterPrivateKey);

        int depth = path.length - 1;
        DeterministicKey ehkey = dh.deriveChild(Arrays.asList(path).subList(0, depth),
                false, true, path[depth]);
        byte[] privkeybytes = ehkey.serializePrivate(MAINNET);
        if (privkeybytes.length == 78){
            String hexStr = bytesToHex(privkeybytes);
            String hextemp = hexStr.substring(hexStr.length() - 64);
            return hextemp;
        }
        else{
            return null;
        }
    }
    private static String getStandardSizeInteger(BigInteger value, int size){
        String hex= value.toString(16);
        if(hex.length()<size){
            int len = size -hex.length();
            String temp = "";
            for(int i=0;i<len;i++){
                temp+="0";
            }
            hex = temp+hex;
        }
        return hex;
    }
    private static String formatEcPublicKey(ECPublicKey publicKey){
        final int SZIE = 64;
        String res = "04"
                + getStandardSizeInteger(publicKey.getW().getAffineX(),SZIE)
                + getStandardSizeInteger(publicKey.getW().getAffineY(),SZIE);
        return res;
    }
    private static int toDigit(final char ch, final int index) throws Exception {
        final int digit = Character.digit(ch, 16);
        if (digit == -1) {
            throw new Exception("Illegal hexadecimal character " + ch + " at index " + index);
        }
        return digit;
    }
    private static byte[] decodeHex(final char[] data) throws Exception{
        final int len = data.length;
        if ((len & 0x01) != 0) {
            throw new Exception("Odd number of characters.");
        }
        final byte[] out = new byte[len >> 1];
        // two characters form the hex value.
        for (int i = 0, j = 0; j < len; i++) {
            int f = toDigit(data[j], j) << 4;
            j++;
            f = f | toDigit(data[j], j);
            j++;
            out[i] = (byte) (f & 0xFF);
        }

        return out;
    }
    private static byte[] EcPublicKey2Bytes(ECPublicKey publicKey){
        String str = formatEcPublicKey(publicKey);
        try {
            return decodeHex(str.toCharArray());
        } catch (Exception e){
            LogFile.logInfo("EcPublicKey2Bytes: "+e.getMessage());
            return null;
        }
    }
    private static String generateAddress(byte[] addressbytes){
        String address = Base58.encode(addressbytes);
        return "OSN"+address;
    }
    public static String GenCompositeAddress(String privkey, String privKeyShadow, String accType){
        ECPrivateKey prvatekey = getEcPrivateKeyFromHex(privkey);
        ECPublicKey publickey = getPublicKeyFromPrivateKey(prvatekey);
        byte[] pub1 = EcPublicKey2Bytes(publickey);
        ECPrivateKey prvatekeyshadow = getEcPrivateKeyFromHex(privKeyShadow);
        ECPublicKey publickeyshadow = getPublicKeyFromPrivateKey(prvatekeyshadow);
        byte[] pub2 = EcPublicKey2Bytes(publickeyshadow);
        byte[] pub2hash = sha256(pub2);

        byte[] address = new byte[2+65+32];
        address[0] = (byte)0x10;
        if(accType.equalsIgnoreCase("group"))
            address[0] |= 0x80;
        else if(accType.equalsIgnoreCase("service"))
            address[0] |= 0x40;
        address[1] = 0;
        System.arraycopy(pub1, 0, address, 2,65);
        System.arraycopy(pub2hash, 0, address, 67,32);
        return generateAddress(address);
    }
    public static String[] createServiceOsnID(){
        String mnemonicStr = createMnemonic();
        ChildNumber[] path1 = {new ChildNumber(23, true), new ChildNumber(1, false)};
        String subPrivateKeyStr1 = GenSubPrivateKey(mnemonicStr, path1);
        ChildNumber[] path2 = {new ChildNumber(24, true), new ChildNumber(1, false)};
        String subPrivateKeyStr2 = GenSubPrivateKey(mnemonicStr, path2);
        String address = GenCompositeAddress(subPrivateKeyStr1, subPrivateKeyStr2, "service");
        String[] serviceOsnID = {address, subPrivateKeyStr1, subPrivateKeyStr2};
        LogFile.logInfo("createServiceOsnID: " + serviceOsnID[0]);
        return serviceOsnID;
    }
}
