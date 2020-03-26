import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.*;

public class osn_imsdemo implements HttpHandler{
    public static void main(String[] args) {
        String osnConnector = "127.0.0.1";
        if(args.length > 1)
            osnConnector = args[1];

        LogFile.initLog("imsdemo.log");
        SqliteUtil.initSqlite();

        osnConnector = "http://"+osnConnector+":8400/osnc";
        osn_imsdemo ims = new osn_imsdemo(osnConnector);
        ims.StartServer();
    }
    private String mOSNConnector;
    private Map<String, UserData> mUserMap = new HashMap<>();              //userHash to UserData
    private Map<String, LinkedList<MsgData>> mHashMsg = new HashMap<>();   //userHash to MsgData List
    private Map<String, MsgData> mHashAuth = new HashMap<>();              //msgHash to MsgData
    //private Map<String, GroupData> mGroupMap = new HashMap<>();            //groupHash to GroupData
    private String mServiceOsnID = null;
    private String mServiceKey = null;

    static class UserData{
        String userID;
        String userHash;
    }
    static class GroupData{
        String groupID;
        String ownID;
        String privateKey;
        String shadowKey;
        String[] userList;
    }
    static class MsgData{
        String command;
        String from;
        String to;
        String timestamp;
        String crypto;
        String content;
        String description;
        String hash;
        String sign;
        String ip;
        LinkedList<MsgData> obj;
    }
    static class MsgAuth{
        String command;
        String from;
        String to;
        String hash;
        String sign;
    }
    private osn_imsdemo(String osnConnector){
        this.mOSNConnector = osnConnector;
    }
    private void StartServer(){
        try {
            String[] serviceOsnID = SqliteUtil.getServiceID();
            if(serviceOsnID == null) {
                serviceOsnID = ECUtils.createServiceOsnID();
                SqliteUtil.setServiceID(serviceOsnID);
            }
            mServiceOsnID = serviceOsnID[0];
            mServiceKey = serviceOsnID[1];

            HttpServer httpServer = HttpServer.create(new InetSocketAddress(8100), 0);
            httpServer.createContext("/ims", this);
            httpServer.start();
            LogFile.logInfo("StartIMSServer port: 8100");
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }

    private JSONObject getBody(InputStream inputStream){
        JSONObject json = null;
        try {
            StringBuilder sb = new StringBuilder();
            byte[] bb = new byte[1024];
            int length;
            while ((length = inputStream.read(bb)) != -1) {
                sb.append(new String(bb, 0, length));
            }
            json = JSONObject.parseObject(sb.toString());
        }
        catch (Exception e){
            json = errExcept(e.getMessage());
        }
        return json;
    }
    private MsgAuth json2Auth(JSONObject jsonObject){
        MsgAuth msgAuth = new MsgAuth();
        msgAuth.command = jsonObject.getString("command");
        msgAuth.from = jsonObject.getString("from");
        msgAuth.to = jsonObject.getString("to");
        msgAuth.hash = jsonObject.getString("hash");
        msgAuth.sign = jsonObject.getString("sign");
        return msgAuth;
    }
    private MsgData json2Msg(JSONObject jsonObject){
        MsgData msgData = new MsgData();
        msgData.command = jsonObject.getString("command");
        msgData.from = jsonObject.getString("from");
        msgData.to = jsonObject.getString("to");
        msgData.crypto = jsonObject.getString("crypto");
        msgData.content = jsonObject.getString("content");
        msgData.description = jsonObject.getString("description");
        msgData.hash = jsonObject.getString("hash");
        msgData.timestamp = jsonObject.getString("timestamp");
        msgData.sign = jsonObject.getString("sign");
        mHashAuth.put(msgData.hash, msgData);
        return msgData;
    }
    private void json2Msg(LinkedList<MsgData> linkedList, JSONObject jsonObject, String ip){
        if(!jsonObject.containsKey("data")) {
            LogFile.logInfo("json2Msg no contains data");
            return;
        }
        JSONArray jsonArray = jsonObject.getJSONArray("data");
        for(int i = 0; i < jsonArray.size(); ++i){
            JSONObject json = jsonArray.getJSONObject(i);
            MsgData msgData = json2Msg(json);
            msgData.ip = ip;
            msgData.obj = linkedList;
            linkedList.add(msgData);
        }
    }
    private JSONObject msg2Json(MsgData msgData){
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("command", msgData.command);
        jsonObject.put("from", msgData.from);
        jsonObject.put("to", msgData.to);
        jsonObject.put("crypto", msgData.crypto);
        jsonObject.put("content", msgData.content);
        jsonObject.put("description", msgData.description);
        jsonObject.put("hash", msgData.hash);
        jsonObject.put("timestamp", msgData.timestamp);
        jsonObject.put("sign", msgData.sign);
        return jsonObject;
    }
    private void msg2Json(LinkedList<MsgData> linkedList, JSONObject jsonObject){
        JSONArray array = new JSONArray();
        for (MsgData msgData : linkedList) {
            JSONObject json = msg2Json(msgData);
            array.add(json);
        }
        jsonObject.put("data", array);
    }
    private void msg2List(LinkedList<MsgData> linkedList, JSONObject jsonObject) {
        JSONArray array = new JSONArray();
        for (MsgData msgData : linkedList)
            array.add(msgData.from);
        jsonObject.put("data", array);
    }

    private JSONObject errok(){return error("success");}
    private JSONObject error(String errCode){
        JSONObject json = new JSONObject();
        json.put("errCode", errCode);
        return json;
    }
    private JSONObject errExcept(String msg){return error(msg);}
    private JSONObject errCommand(){
        return error("unknow command");
    }
    private JSONObject errResponse(int errCode){
        return error("Response error" + String.valueOf(errCode));
    }
    private JSONObject errFormat(){
        return error("error format");
    }
    private JSONObject errNoUser(){return error("error user");}
    private JSONObject errNoData(){return error("error data");}
    private JSONObject errVerify(){return error("sign verify failed");}
    private JSONObject errUpdatetDB(){return error("update db error");}

    private void respone(HttpExchange exchange, JSONObject json){
        try {
            exchange.sendResponseHeaders(200, 0);
            OutputStream outputStream = exchange.getResponseBody();
            outputStream.write(json.toString().getBytes());
            outputStream.close();
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
    private void setHashmsg(String hash, JSONObject json, String ip){
        LinkedList<MsgData> linkedList = mHashMsg.computeIfAbsent(hash, k -> new LinkedList<>());
        json2Msg(linkedList, json, ip);
    }
    private void getUsermsg(String hash, JSONObject json){
        LinkedList<MsgData> linkedList = mHashMsg.computeIfAbsent(hash, k -> new LinkedList<>());
        msg2Json(linkedList, json);
        linkedList.clear();
    }
    private void getUserlist(String hash, JSONObject json){
        LinkedList<MsgData> linkedList = mHashMsg.computeIfAbsent(hash, k -> new LinkedList<>());
        msg2List(linkedList, json);
    }

    private JSONObject doPost(String urlString, JSONObject json){
        try{
            URL url = new URL(urlString);
            HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
            httpURLConnection.setRequestMethod("POST");
            httpURLConnection.setRequestProperty("accept", "*/*");
            httpURLConnection.setDoOutput(true);
            httpURLConnection.setDoInput(true);
            //httpURLConnection.setConnectTimeout(5000);
            //httpURLConnection.setReadTimeout(5000);
            if(json != null)
                httpURLConnection.getOutputStream().write(json.toString().getBytes());
            else
                httpURLConnection.connect();
            if (httpURLConnection.getResponseCode() != 200){
                json = errResponse(httpURLConnection.getResponseCode());
            }
            else {
                InputStream inputStream = httpURLConnection.getInputStream();
                json = getBody(inputStream);
            }
        }
        catch (Exception e){
            e.printStackTrace();
            json = errExcept(e.getMessage());
        }
        return json;
    }
    private boolean verifySign(MsgData msgData, MsgAuth msgAuth){
        boolean auth = false;
        try {
            auth = ECUtils.verifySign(msgData.to, msgData.hash, msgAuth.sign);
        }
        catch (Exception e){
            LogFile.logInfo("verify sign:" + e.getMessage());
        }
        LogFile.logInfo("verifySign:" + auth + ", hash: " + msgAuth.hash + ", sign: " + msgAuth.sign);
        return auth;
    }
    private void MsgComplete(HttpExchange exchange, JSONObject json){
        try {
            MsgAuth msgAuth = json2Auth(json);
            if(msgAuth.from == null){
                LogFile.logInfo("MsgComplete: format error -> "+exchange.getRemoteAddress().toString());
                respone(exchange, errFormat());
                return;
            }
            LogFile.logInfo("MsgComplete from: " + msgAuth.from + ", to: " + msgAuth.to);
            String toHash = IDUtil.GetHash(msgAuth.to);
            LinkedList<MsgData> linkedList = mHashMsg.get(toHash);
            if(linkedList == null){
                LogFile.logInfo("MsgComplete: no find data");
                respone(exchange, errNoData());
                return;
            }
            MsgData msgData = mHashAuth.get(msgAuth.hash);
            if(msgData == null){
                LogFile.logInfo("MsgComplete: no find data");
                respone(exchange, errNoData());
                return;
            }
            if(msgData.ip == null){
                json.clear();
                if(verifySign(msgData, msgAuth))
                    msgData.obj.remove(msgData);
                else
                    json = errVerify();
            }
            else{
                msgData.obj.remove(msgData);
                json.put("ip", msgData.ip);
                json = doPost(mOSNConnector, json);
            }
        }
        catch (Exception e){
            LogFile.logInfo("MsgComplete:"+e.getMessage());
            json = errExcept(e.getMessage());
        }
        respone(exchange, json);
    }
    private void GetMessage(HttpExchange exchange, JSONObject json){
        try {
            String userHash = null;
            String user = json.getString("user");
            if(user == null){
                userHash = json.getString("to");
                if(userHash == null){
                    LogFile.logInfo("GetMessage: unknow user");
                    respone(exchange, errNoUser());
                    return;
                }
                user = "<remote>";
            }
            else
                userHash = IDUtil.GetHash(user);
            //logInfo("[GetMessage] user: "+ user +", userHash: "+userHash);

            json.clear();
            json.put("errCode", "0");
            getUsermsg(userHash, json);
            //logInfo("[message] " + json.toString());
        }
        catch (Exception e){
            LogFile.logInfo("GetMessage:"+e.getMessage());
            json = errExcept(e.getMessage());
        }
        respone(exchange, json);
    }
    private void GetMsgList(HttpExchange exchange, JSONObject json){
        String hash = json.getString("hash");
        LogFile.logInfo("GetMsgList <- hash: " + hash);
        json.clear();
        json.put("command", "userlist");
        getUserlist(hash, json);
        respone(exchange, json);
    }
    private void SendMessage(HttpExchange exchange, JSONObject json){
        try {
            if(!json.containsKey("from") || !json.containsKey("to")){
                LogFile.logInfo("SendMessage: format error -> " + exchange.getRemoteAddress().toString());
                respone(exchange, errFormat());
                return;
            }
            MsgData msgData = json2Msg(json);
            String toHash = IDUtil.GetHash(msgData.to);
            LinkedList<MsgData> linkedList = mHashMsg.computeIfAbsent(toHash, k -> new LinkedList<>());
            linkedList.add(msgData);
            msgData.obj = linkedList;
            LogFile.logInfo("SendMessage from: "+ msgData.from +", to: "+ msgData.to);
            json = doPost(mOSNConnector, json);
        }
        catch (Exception e){
            LogFile.logInfo("SendMessage:"+e.getMessage());
            json = errExcept(e.getMessage());
        }
        respone(exchange, json);
    }
    private void FindUser(HttpExchange exchange, JSONObject json){
        String hash = json.getString("hash");
        String ip = json.getString("ip");

        LogFile.logInfo("FindUser ip: " + ip + ", hash: " + hash);
        respone(exchange, errok());

        if(mUserMap.containsKey(hash)) {
            json.clear();
            json.put("command", "getmsglist");
            json.put("hash", hash);
            json.put("ip", ip);
            json = doPost(mOSNConnector, json);

            LogFile.logInfo("FindUser: getmsglist -> ip: " + ip + ", has:" + hash);

            UserData userData = mUserMap.get(hash);

            json.clear();
            json.put("command", "getmsg");
            json.put("to", userData.userHash);
            json.put("user", userData.userID);
            json.put("from", "");
            json.put("ip", ip);
            LogFile.logInfo("Finder: " + json.toString());
            json = doPost(mOSNConnector, json);
            setHashmsg(hash, json, ip);

            LogFile.logInfo("FindUser: getmsg -> user: " + userData.userID);
            //logInfo("[message] " + json);
        }
    }
    private void Login(HttpExchange exchange, JSONObject json){
        String userID = json.getString("user");
        UserData userData = mUserMap.computeIfAbsent(userID, k -> new UserData());
        userData.userID = userID;
        userData.userHash = IDUtil.GetHash(userID);
        mUserMap.put(userData.userHash, userData);
        //logInfo("[Login] user: " + userID + ", userHash: " + userData.userHash);
        json.clear();
        json.put("errCode", "0");
        json.put("userHash", userData.userHash);
        json.put("serviceID", mServiceOsnID);
        respone(exchange, json);
    }
    private void CreateGroup(HttpExchange exchange, JSONObject json){
        String data = json.getString("data");
        String owner = json.getString("owner");
        String sign = json.getString("sign");
        if(!ECUtils.verifySign(owner, data, sign)){
            LogFile.logInfo("CreateGroup: verify sign failed, owner="+owner);
            respone(exchange, errVerify());
            return;
        }

        byte[] decData = ECUtils.ECDecrypt(mServiceKey, data);
        String groupInfo = new String(decData);
        json = JSONObject.parseObject(groupInfo);
        json.put("owner", owner);
        json.put("userList", "");
        LogFile.logInfo("CreateGroup: groupID="+json.getString("groupID")+", owner="+owner);
        if(SqliteUtil.insertGroup(json))
            respone(exchange, errok());
        else
            respone(exchange, errUpdatetDB());
    }
    public void handle(HttpExchange exchange) {
        String requestMethod = exchange.getRequestMethod();
        if(requestMethod.equalsIgnoreCase("POST")){
            InputStream inputStream = exchange.getRequestBody();
            JSONObject json = getBody(inputStream);
            if(json.containsKey("errCode")){
                respone(exchange, json);
                return;
            }
            String command = json.getString("command");
            if ("getmsg".equalsIgnoreCase(command)) {
                GetMessage(exchange, json);
            } else if ("getmsglist".equalsIgnoreCase(command)) {
                GetMsgList(exchange, json);
            } else if ("login".equalsIgnoreCase(command)) {
                Login(exchange, json);
            } else if ("message".equalsIgnoreCase(command)) {
                SendMessage(exchange, json);
            } else if ("complete".equalsIgnoreCase(command)) {
                MsgComplete(exchange, json);
            } else if ("finduser".equalsIgnoreCase(command)) {
                FindUser(exchange, json);
            } else if("creategroup".equalsIgnoreCase(command)){
                CreateGroup(exchange, json);
            } else {
                respone(exchange, errCommand());
            }
        }
    }
}
