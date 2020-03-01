import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.encoders.Hex;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class ECUtils {
    public static final String SIGN_ALGORITHM = "SHA256withECDSA";
    public static final String ECDSA = "ECDSA";
    public static final String PRIME_256V1 = "prime256v1";
    public static final String ALGORITHM = "EC";
    public static final String SPACE_NAME= "prime256v1";// eq prime256v1

    /**
     * 根据公钥字节码获取公钥对象
     *
     * @param pubKey 公钥字节码
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static PublicKey getPublicKeyFromBytes(byte[] pubKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(PRIME_256V1);
        KeyFactory kf = KeyFactory.getInstance(ECDSA, new BouncyCastleProvider());
        ECNamedCurveSpec params = new ECNamedCurveSpec(PRIME_256V1, spec.getCurve(), spec.getG(), spec.getN());
        ECPoint point = ECPointUtil.decodePoint(params.getCurve(), pubKey);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
        ECPublicKey pk = (ECPublicKey) kf.generatePublic(pubKeySpec);
        return pk;
    }
    public static ECPublicKey getPulicKeyFromAddress(String address){
        //
        String flag = address.substring(0, 3);
        if (!flag.equals("OSN"))
            return null;
        // decode base58
        String base58str = address.substring(3);
        try {
            byte[] data = Base58.decode(base58str);
            byte[] pub = null;
            if (data[0]==0x11)
            {
                if (data[1]==4 && data.length >= 66)
                {
                    pub = new byte[65];
                    System.arraycopy(data,1, pub,0, 65);
                }
            } else if (data[0]==4 && data.length >= 65){
                pub = new byte[65];
                System.arraycopy(data,0, pub,0, 65);
            }

            if (pub != null)
            {
                // 转化成公钥
                return getPublicKeyFromHex(pub);
            }
        } catch (Exception e)
        {
            return null;
        }
        return null;
    }
    public static ECPublicKey getPublicKeyFromHex(byte[] pubKey) {
        ECPublicKey pk;
        try {
            Provider provider = new BouncyCastleProvider();

//			byte[] pubKey = Hex.decodeHex(hexstr.toCharArray());
//            byte[] pubKey = Hex.decode(new String(hexstr.toCharArray()));
            org.bouncycastle.jce.spec.ECNamedCurveParameterSpec spec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec(SPACE_NAME);
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM, provider);
            org.bouncycastle.jce.spec.ECNamedCurveSpec params = new org.bouncycastle.jce.spec.ECNamedCurveSpec(SPACE_NAME, spec.getCurve(), spec.getG(), spec.getN());
            ECPoint point =  org.bouncycastle.jce.ECPointUtil.decodePoint(params.getCurve(), pubKey);
            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
            pk = (ECPublicKey) kf.generatePublic(pubKeySpec);
            return pk;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    /**
     * 根据16进制公钥字符串，原始数据，签名验签
     *
     * @param data   原数据
     * @param pubKey 公钥
     * @param sig    签名
     * @return
     * @throws Exception
     */
    public static boolean verifySignFromHexStringKey(byte[] data, byte[] pubKey, byte[] sig) throws NoSuchAlgorithmException, InvalidKeySpecException,InvalidKeyException,SignatureException{
        Signature ecdsaVerify = Signature.getInstance(SIGN_ALGORITHM, new BouncyCastleProvider());
        ecdsaVerify.initVerify(getPublicKeyFromBytes(pubKey));
        ecdsaVerify.update(data);
        return ecdsaVerify.verify(sig);
    }
    public static boolean isHttpUrl(String urls) {
        boolean isurl = false;
        String regex = "^((https|http|ftp|rtsp|mms)?:\\/\\/)[^\\s]+";//设置正则表达式
        Pattern pat = Pattern.compile(regex.trim());//比对
        Matcher mat = pat.matcher(urls.trim());
        isurl = mat.matches();//判断是否匹配
        return isurl;
    }
    public static void main(String[] args) throws Exception {
        String key = "S3pdXvXMMomhTfprQQqsMFY5JKpPuD7rYaWic2SacvhU584nVbXijX8ZoVmNqTwdx34qphwdbWHNgbqXGRQmNhxp";
        byte[] pkey = Base58.decode(key);
        String message = "CFWCHAINS3pdXvXMMomhTfprQQqsMFY5JKpPuD7rYaWic2SacvhU584nVbXijX8ZoVmNqTwdx34qphwdbWHNgbqXGRQmNhxpCFWCHAINRwEZ4pTJFB5HDkyKEVUk1375YvLDkaP8hy9g8xkAEhKXW7rX5HNzF4tMMU8HVpzuLcaYe1AiW5U3apEEXKBhBqJG94588890-3545-4d80-a5a4-382ff4e41343false";
        String signatureStr = "304502206ae8879ad6270b73180f45d778089ba45ce6f0a1e7e232dff84e96f50be17cdb022100f4926561010c5d469192931c8c4d73b30cba1f22d6c630353a8a2031f56cd86c";
        byte[] sign = Hex.decode(signatureStr);
        boolean isValid = verifySignFromHexStringKey(message.getBytes(), pkey, sign);
        boolean result=isHttpUrl(message);
        System.out.println(result);
        System.out.println("isValid:" + isValid);
    }
}
