package com.ospn.utils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.ospn.common.ECUtils;
import com.ospn.common.OsnUtils;
import com.ospn.data.*;

import static com.ospn.Constant.*;
import static com.ospn.common.OsnUtils.*;
import static com.ospn.core.IMData.*;

public class CryptUtils {
    public static void toLocalMessage(JSONObject json, String keySender, String keyRecver) {
        byte[] aesKey = aesDecrypt(json.getString("aeskey"), sha256(keySender.getBytes()));
        String webKey = aesEncrypt(aesKey, sha256(keyRecver.getBytes()));
        json.put("sign", aesEncrypt(json.getString("hash"), keyRecver));
        json.put("aeskey", webKey);
        json.put("crypto", "aes");
    }

    public static void toAesMessage(JSONObject json, String key) {
        byte[] aesKey = ECUtils.ecDecrypt2(key, json.getString("ecckey"));
        String webKey = aesEncrypt(aesKey, sha256(key.getBytes()));
        json.put("sign", aesEncrypt(json.getString("hash"), key));
        json.put("aeskey", webKey);
        json.put("crypto", "aes");
    }

    public static void toEccMessage(JSONObject json, String key) {
        byte[] aesKey = aesDecrypt(json.getString("aeskey"), sha256(key.getBytes()));
        //logInfo("aesKey: "+aesKey.length+", to: "+json.getString("to"));
        String eccKey = ECUtils.ecEncrypt2(json.getString("to"), aesKey);
        json.put("sign", ECUtils.osnSign(key, json.getString("hash").getBytes()));
        json.put("ecckey", eccKey);
        json.put("crypto", "ecc-aes");
    }

    public static JSONObject packMessage(JSONObject json, String from, String to, String key) {
        JSONObject data = new JSONObject();
        data.put("originalUser", json.getString("from"));
        data = packMessage(json, from, to, data, key);
        assert data != null;
        data.put("hash0", json.getString("hash"));
        return data;
    }

    public static JSONObject packMessage(JSONObject json, String from, String to, JSONObject dataWrap, String key) {
        try {
            JSONObject data = new JSONObject();
            data.put("command", json.getString("command"));
            data.put("ver", json.getString("ver"));
            data.put("from", from);
            data.put("to", to);
            data.put("timestamp", json.getString("timestamp"));

            byte[] aesKey;
            String content;
            if (dataWrap == null) {
                dataWrap = new JSONObject();
            }
            String crypto = json.getString("crypto");
            if (crypto == null || crypto.equalsIgnoreCase("none")) {
                aesKey = getAesKey();
                content = json.getString("content");
            } else {
                aesKey = ECUtils.ecDecrypt2(key, json.getString("ecckey"));
                content = json.getString("content");
                content = new String(aesDecrypt(content, aesKey));
            }
            data.put("ecckey", ECUtils.ecEncrypt2(to, aesKey));
            data.put("crypto", "ecc-aes");

            JSONObject jsonWrap = JSON.parseObject(content);
            for (String s : dataWrap.keySet())
                jsonWrap.put(s, dataWrap.get(s));
            content = jsonWrap.toString();

            data.put("content", aesEncrypt(content.getBytes(), aesKey));
            String calc = from + to + json.getString("timestamp") + data.getString("content");
            String hash = ECUtils.osnHash(calc.getBytes());
            String sign = ECUtils.osnSign(key, hash.getBytes());
            data.put("hash", hash);
            data.put("sign", sign);

            return data;
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    public static JSONObject wrapMessage(String command, String from, String to, JSONObject data, String key, JSONObject original) {
        JSONObject json = new JSONObject();
        CommandData commandData = getCommand(command);
        json.put("command", command);
        json.put("ver", commandData == null ? "1" : commandData.version);
        json.put("from", from);
        json.put("to", to);

        if (data == null)
            data = new JSONObject();
        json.put("content", data.toString());

        long timestamp = System.currentTimeMillis();
        String calc = from + to + timestamp + data;
        String hash = ECUtils.osnHash(calc.getBytes());

        json.put("timestamp", timestamp);
        json.put("hash", hash);

        String sign = ECUtils.osnSign(key, hash.getBytes());
        json.put("sign", sign);
        json.put("crypto", "none");

        if (original != null) {
            json.put("id", original.getString("id"));
            json.put("errCode", "0:success");
        }

        return json;
    }

    public static JSONObject makeMessage(String command, String from, String to, JSONObject data, String key, JSONObject original) {
        return makeMessage(command, from, to, data.toString(), key, original);
    }

    public static JSONObject makeMessage(String command, String from, String to, String data, String key, JSONObject original) {
        JSONObject json = new JSONObject();
        CommandData commandData = getCommand(command);
        json.put("command", command);
        json.put("ver", commandData == null ? "1" : commandData.version);
        json.put("from", from);
        json.put("to", to);

        if (data == null) {
            json.put("content", "{}");
            json.put("crypto", "none");
        } else {
            byte[] aesKey = getAesKey();
            String encData = aesEncrypt(data.getBytes(), aesKey);
            json.put("content", encData);
            json.put("crypto", "ecc-aes");

            String encKey = ECUtils.ecEncrypt2(to, aesKey);
            json.put("ecckey", encKey);
        }
        long timestamp = System.currentTimeMillis();
        String calc = from + to + timestamp + json.getString("content");
        String hash = ECUtils.osnHash(calc.getBytes());

        json.put("timestamp", timestamp);
        json.put("hash", hash);

        String sign = ECUtils.osnSign(key, hash.getBytes());
        json.put("sign", sign);

        if (original != null) {
            json.put("id", original.getString("id"));
            json.put("errCode", "0:success");
        }

        return json;
    }

    public static JSONObject takeMessage(JSONObject json) {
        try {
            String crypto = json.getString("crypto");
            if (crypto.equalsIgnoreCase("none"))
                return JSON.parseObject(json.getString("content"));
            byte[] aesKey;
            if (crypto.equalsIgnoreCase("aes")) {
                CryptData cryptData = getUserData(json.getString("from"));
                aesKey = aesDecrypt(json.getString("aeskey"), sha256(cryptData.osnKey.getBytes()));
            } else if (crypto.equalsIgnoreCase("ecc-aes")) {
                String osnID = json.getString("to");
                CryptData cryptData = getCryptData(osnID);
                if (cryptData != null) {
                    aesKey = ECUtils.ecDecrypt2(cryptData.osnKey, json.getString("ecckey"));
                } else {
                    cryptData = getCryptData(json.getString("from"));
                    if (cryptData == null) {
                        OsnUtils.logInfo("no find osnID: " + osnID);
                        return null;
                    }
                    aesKey = aesDecrypt(json.getString("aeskey"), sha256(cryptData.osnKey.getBytes()));
                }
            } else {
                OsnUtils.logInfo("unsupport crypto");
                return null;
            }
            if (aesKey == null || !json.containsKey("content"))
                return null;
            byte[] data = aesDecrypt(json.getString("content"), aesKey);
            return JSON.parseObject(new String(data));
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    public static ErrorData checkMessage(JSONObject json) {
        try {
            String from = json.getString("from");
            String to = json.getString("to");
            String timestamp = json.getString("timestamp");
            String content = json.getString("content");
            String calc = from + to + timestamp + content;
            String hash = ECUtils.osnHash(calc.getBytes());
            if (!hash.equalsIgnoreCase(json.getString("hash"))) {
                logInfo("hash no equals " + hash + ":" + json.getString("hash"));
                return E_hashVerify;
            }
            String crypto = json.getString("crypto");
            if (crypto == null)
                return E_needCrypto;
            String sign = json.getString("sign");
            if (crypto.equalsIgnoreCase("aes")) {
                UserData userData = getUserData(from);
                sign = aesDecrypt(sign, userData.osnKey);
                if (sign == null)
                    return E_signVerify;
                if (!sign.equalsIgnoreCase(hash))
                    return E_signVerify;
            } else if (crypto.startsWith("ecc-aes")) {
                if (!ECUtils.osnVerify(from, hash.getBytes(), sign))
                    return E_signVerify;
            }
        } catch (Exception e) {
            logError(e);
        }
        return null;
    }
}
