package com.ospn.server;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

import com.ospn.OsnIMServer;
import com.ospn.common.ECUtils;
import com.ospn.common.OsnUtils;
import com.ospn.data.*;
import com.ospn.utils.HttpUtils;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.*;

import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import static com.ospn.Constant.*;
import static com.ospn.OsnIMServer.Inst;
import static com.ospn.common.OsnUtils.*;
import static com.ospn.core.IMData.*;
import static com.ospn.utils.CryptUtils.checkMessage;
import static com.ospn.utils.CryptUtils.makeMessage;
import static io.netty.util.CharsetUtil.UTF_8;

public class OsnAdminServer extends SimpleChannelInboundHandler<FullHttpRequest> {
    private final String adminKey;
    private static final String versionInfo = "v1.1 2021-3-27, base line, long link, findOsnID verify, osnid sync, keywordFilter";
    private String[] mainLitapps = null;

    public OsnAdminServer() {
        adminKey = prop.getProperty("adminKey");
        String litapps = prop.getProperty("mainLitapps", null);
        if (litapps != null) {
            mainLitapps = litapps.split(";");
        }
    }

    public static UserData RegsiterUser(String userName, String password) {
        String[] newOsnID = ECUtils.createOsnID("user");
        UserData userData = new UserData();
        assert newOsnID != null;
        userData.osnID = newOsnID[0];
        userData.osnKey = newOsnID[1];
        userData.name = userName;
        userData.password = Base64.getEncoder().encodeToString(sha256(password.getBytes()));
        userData.aesKey = Base64.getEncoder().encodeToString(sha256(String.valueOf(System.currentTimeMillis()).getBytes()));
        userData.msgKey = Base64.getEncoder().encodeToString(sha256(String.valueOf(System.currentTimeMillis()).getBytes()));
        userData.displayName = userName;
        userData.urlSpace = urlSpace;
        if (!db.insertUser(userData))
            return null;
        return userData;
    }

    private JSONObject replay(ErrorData error, String data) {
        JSONObject json = new JSONObject();
        json.put("errCode", error == null ? "0:success" : error.toString());
        json.put("data", data);
        if (error != null)
            logInfo3(error.toString());
        return json;
    }

    private JSONObject getData(JSONObject json) {
        String data = json.getString("data");
        return JSON.parseObject(OsnUtils.aesDecrypt(data, adminKey));
    }

    private void setData(JSONObject json) {
        String data = json.getString("data");
        if (data != null)
            json.put("data", OsnUtils.aesEncrypt(data, adminKey));
    }

    private JSONObject getOnlineUser(JSONObject json) {
        try {
            JSONArray array = new JSONArray();
            array.addAll(userMap.values());
            json.clear();
            json.put("userList", array);
            json = replay(null, json.toString());
            return json;
        } catch (Exception e) {
            logError(e);
            return replay(new ErrorData("-1", e.toString()), null);
        }
    }

    private JSONObject getUserInfo(JSONObject json) {
        try {
            String userID = json.getString("userID");
            UserData userData = getUserData(userID);
            if (userData == null)
                return replay(E_userNoFind, null);
            json.clear();
            json.put("userInfo", userData);
            return replay(null, json.toString());
        } catch (Exception e) {
            logError(e);
            return replay(new ErrorData("-1", e.toString()), null);
        }
    }

    private JSONObject getGroupInfo(JSONObject json) {
        try {
            String groupID = json.getString("groupID");
            GroupData groupData = getGroupData(groupID);
            if (groupData == null)
                return replay(E_userNoFind, null);
            json.clear();
            json.put("groupInfo", groupData);
            return replay(null, json.toString());
        } catch (Exception e) {
            logError(e);
            return replay(new ErrorData("-1", e.toString()), null);
        }
    }

    private JSONArray loadKeywords() {
        JSONArray keywords = null;
        try {
            String keywordFile = prop.getProperty("keywordFilter");
            FileInputStream fileInputStream = new FileInputStream(keywordFile);
            byte[] data = new byte[fileInputStream.available()];
            fileInputStream.read(data);
            keywords = JSON.parseArray(new String(data));
            logInfo("keywords: " + keywords.size());
            fileInputStream.close();
        } catch (Exception e) {
            logError(e);
        }
        return keywords == null ? new JSONArray() : keywords;
    }

    private JSONObject loadAppVersion() {
        JSONObject version = null;
        try {
            String keywordFile = prop.getProperty("appVersion");
            FileInputStream fileInputStream = new FileInputStream(keywordFile);
            byte[] data = new byte[fileInputStream.available()];
            fileInputStream.read(data);
            version = JSON.parseObject(new String(data));
            fileInputStream.close();
        } catch (Exception e) {
            logError(e);
        }
        return version;
    }

    private JSONObject resetpwd(JSONObject json) {
        try {
            String username = json.getString("username");
            String userID = json.getString("userID");
            String password = json.getString("password");
            UserData userData = userID == null ? getUserDataByName(username) : getUserData(userID);
            if (userData == null)
                return replay(E_userNoFind, null);
            String passwordOld = userData.password;
            userData.password = Base64.getEncoder().encodeToString(sha256(password.getBytes()));
            if (!db.updateUser(userData, Collections.singletonList("password"))) {
                userData.password = passwordOld;
                return replay(E_dataBase, null);
            }
            logInfo("userID: " + userID + ", name: " + username);
            return replay(null, null);
        } catch (Exception e) {
            logError(e);
            return replay(new ErrorData("-1", e.toString()), null);
        }
    }

    private JSONObject register(JSONObject json) {
        try {
            String username = json.getString("username");
            String password = json.getString("password");

            if (username == null || password == null)
                return replay(E_missData, null);
            else if (db.isRegisterName(username)) {
                UserData userData = db.readUserByName(username);
                json = new JSONObject();
                json.put("osnID", userData.osnID);
                return replay(E_userExist, json.toString());
            }

            UserData userData = RegsiterUser(username, password);
            if (userData == null)
                return replay(E_registFailed, null);
            OsnIMServer.Inst.pushOsnID(userData);
            logInfo("register user: " + username + ", osnID: " + userData.osnID);

            json = new JSONObject();
            json.put("osnID", userData.osnID);
            return replay(null, json.toString());
        } catch (Exception e) {
            logError(e);
            return replay(new ErrorData("-1", e.toString()), null);
        }
    }

    private JSONObject sendNotify(JSONObject json) {
        try {
            String command = json.getString("command");
            CommandData commandData = getCommand(command);
            if (commandData == null)
                return replay(E_errorCmd, null);
            long timestamp = Long.parseLong(json.getString("timestamp"));
            if (timestamp - System.currentTimeMillis() > 5 * 60 * 1000)
                return replay(E_timeSync, null);
            String to = json.getString("to");
            String from = json.getString("from");
            if (from == null || to == null || !isOsnID(from) || !isOsnID(to))
                return replay(E_missData, null);
            ErrorData error = checkMessage(json);
            if (error != null)
                return replay(error, null);
            return replay(Inst.sendNotify(json), null);
        } catch (Exception e) {
            logError(e);
            return replay(new ErrorData("-1", e.toString()), null);
        }
    }

    private JSONObject userNotify(JSONObject json) {
        try {
            String to = json.getString("to");
            String from = json.getString("from");
            String osnKey = json.getString("osnKey");
            String content = json.getString("content");
            if (to == null || from == null || osnKey == null)
                return replay(E_missData, null);
            JSONObject data = makeMessage("Message", from, to, content, osnKey, null);
            return replay(Inst.sendNotify(data), null);
        } catch (Exception e) {
            logError(e);
            return replay(new ErrorData("-1", e.toString()), null);
        }
    }

    private JSONObject getFriends(JSONObject json) {
        try {
            String userID = json.getString("userID");
            UserData userData = getUserData(userID);
            if (userData == null)
                return replay(E_userNoFind, null);
            json.clear();
            json.put("friends", userData.friends);
            return replay(null, json.toString());
        } catch (Exception e) {
            logError(e);
            return replay(new ErrorData("-1", e.toString()), null);
        }
    }

    private JSONObject registerLitapp(JSONObject json) {
        try {
            LitappData litappData = LitappData.toObject(json);
            if (litappData.osnID == null || litappData.osnKey == null || litappData.name == null || litappData.url == null || litappData.portrait == null) {
                logInfo("data: " + json);
                return replay(E_missData, null);
            }

            LitappData litappDataNew = getLitappData(litappData.osnID);
            if (litappDataNew != null)
                logError("exists litappID: " + litappData.osnID);
            if (!db.insertLitapp(litappData))
                return replay(E_dataBase, null);
            logInfo("name: " + litappData.name + ", serviceID: " + litappData.osnID);
            litappMap.put(litappData.osnID, litappData);
            return replay(null, null);
        } catch (Exception e) {
            logError(e);
            return replay(new ErrorData("-1", e.toString()), null);
        }
    }

    private JSONObject deleteLitapp(JSONObject json) {
        try {
            String osnID = json.getString("osnID");
            if (osnID == null) {
                logInfo("data: " + json);
                return replay(E_missData, null);
            }

            LitappData litappData = getLitappData(osnID);
            if (litappData == null) {
                logError("no exist litappID: " + osnID);
                return replay(E_dataNoFind, null);
            }

            if (!db.deleteLitapp(osnID))
                return replay(E_dataBase, null);
            logInfo("osnID: " + osnID);
            litappMap.remove(osnID);
            return replay(null, null);
        } catch (Exception e) {
            logError(e);
            return replay(new ErrorData("-1", e.toString()), null);
        }
    }

    private JSONObject getLitappList(JSONObject json) {
        try {
            JSONObject data = new JSONObject();
            String litappID = json.getString("litappID");
            if (litappID != null) {
                LitappData litappData = getLitappData(litappID);
                data.put("litappList", Collections.singletonList(litappData));
                logInfo("data: " + litappData);
            } else {
                List<LitappData> litappDataList = db.listLitapp();
                data.put("litappList", litappDataList);
                logInfo("size: " + litappDataList.size());
            }
            return replay(null, data.toString());
        } catch (Exception e) {
            logError(e);
            return replay(new ErrorData("-1", e.toString()), null);
        }
    }

    private JSONObject createOsnID(JSONObject json) {
        try {
            String type = json.getString("type");
            if (type == null)
                return replay(E_missData, null);
            String[] osnID = ECUtils.createOsnID(type);
            JSONObject data = new JSONObject();
            assert osnID != null;
            data.put("osnID", osnID[0]);
            data.put("oskKey", osnID[1]);
            return replay(null, data.toString());
        } catch (Exception e) {
            logError(e);
            return replay(new ErrorData("-1", e.toString()), null);
        }
    }

    private JSONObject isRegister(JSONObject json) {
        try {
            String userID = json.getString("userID");
            UserData userData = getUserData(userID);
            if (userData == null)
                return replay(E_userNoFind, null);
            json.clear();
            return replay(null, json.toString());
        } catch (Exception e) {
            logError(e);
            return replay(new ErrorData("-1", e.toString()), null);
        }
    }

    private JSONObject setUserInfo(JSONObject json) {
        try {
            String userID = json.getString("userID");
            UserData userData = getUserData(userID);
            if (userData == null)
                return replay(E_userNoFind, null);
            UserData userKeys = new UserData();
            userKeys.osnID = userID;
            List<String> keys = userData.parseKeys(json, userKeys);
            if(keys.isEmpty()){
                return replay(E_missData, null);
            }
            logInfo("keys: "+keys);
            if (!db.updateUser(userKeys, keys)) {
                return replay(E_dataBase, null);
            }
            return replay(null, null);
        } catch (Exception e) {
            logError(e);
            return replay(new ErrorData("-1", e.toString()), null);
        }
    }

    public JSONObject handleAdmin(JSONObject json) {
        JSONObject result;
        try {
            result = getData(json);
            switch (json.getString("command")) {
                case "register":
                    result = register(result);
                    break;
                case "resetPassword":
                    result = resetpwd(result);
                    break;
                case "userOnline":
                    result = getOnlineUser(result);
                    break;
                case "userInfo":
                    result = getUserInfo(result);
                    break;
                case "groupInfo":
                    result = getGroupInfo(result);
                    break;
                case "sendNotify":
                    result = sendNotify(result);
                    break;
                case "userNotify":
                    result = userNotify(result);
                    break;
                case "getFriends":
                    result = getFriends(result);
                    break;
                case "registerLitapp":
                    result = registerLitapp(result);
                    break;
                case "deleteLitapp":
                    result = deleteLitapp(result);
                    break;
                case "litappList":
                    result = getLitappList(result);
                    break;
                case "createOsnID":
                    result = createOsnID(result);
                    break;
                case "isRegister":
                    result = isRegister(result);
                    break;
                case "setUserInfo":
                    result = setUserInfo(result);
                    break;
                default:
                    result = replay(E_errorCmd, null);
                    break;
            }
            setData(result);
        } catch (Exception e) {
            result = replay(new ErrorData("-1", e.toString()), null);
            logError(e);
        }
        return result;
    }

    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest fullHttpRequest) {
        try {
            JSONObject json;
            if (fullHttpRequest.method() == HttpMethod.POST) {
                String content = fullHttpRequest.content().toString(UTF_8);
                json = JSON.parseObject(content);
                json = handleAdmin(json);
            } else if (fullHttpRequest.method() == HttpMethod.GET) {
                json = new JSONObject();
                String uri = fullHttpRequest.uri();
                if (uri.equalsIgnoreCase("/serviceid")) {
                    json.put("serviceID", service.osnID);
                } else if (uri.equalsIgnoreCase("/version")) {
                    json.put("version", versionInfo);
                } else if (uri.equalsIgnoreCase("/mainLitapps")) {
                    json.put("litapps", mainLitapps);
                } else if (uri.equalsIgnoreCase("/keywordFilter")) {
                    JSONArray keywords = loadKeywords();
                    json.put("keywords", keywords);
                } else if (uri.equalsIgnoreCase("/appVersion")) {
                    json.put("appVersion", loadAppVersion());
                } else if (uri.equalsIgnoreCase("/helpInfo")) {
                    json.put("helpIn", helpIn);
                    json.put("helpOut", helpOut);
                } else
                    json.put("errCode", "unsupport uri");
            } else {
                json = new JSONObject();
                json.put("errCode", "unsupport method");
            }
            HttpUtils.sendReply(ctx, json);
        } catch (Exception e) {
            logError(e);
        }
    }

    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        super.exceptionCaught(ctx, cause);
        ctx.close();
    }
}
