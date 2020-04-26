import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class osn_imsdemo {
    public static void main(String[] args) {
        osn_imsdemo ims = new osn_imsdemo();
        ims.mOsnConnector = "127.0.0.1";
        ims.mLogFileName = "imsdemo.log";
        if(args.length > 1)
            ims.mOsnConnector = args[0];
        ims.StartServer();

        if(args.length > 1 && args[args.length-1].equalsIgnoreCase("test")){
            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                while (true) {
                    System.out.print(">");
                    String line = reader.readLine();
                    System.out.print(line);
                    if (line.equalsIgnoreCase("osnid")) {
                        String[] osnid = ECUtils.createOsnID("");
                        System.out.println("OsnID: " + osnid[0]);
                    } else if (line.equalsIgnoreCase("exit")) {
                        break;
                    }
                }
            }
            catch (Exception e){
                e.printStackTrace();
            }
        }
    }

    private Map<String, UserData> mUserMap = new HashMap<>();           //userHash to UserData
    private Map<String, List<JSONObject>> mHashMsg = new HashMap<>();   //userHash to MsgData List
    private String mServiceOsnID = null;
    private String mServiceKey = null;
    private ExecutorService mExecutorService  = Executors.newFixedThreadPool(2);
    private Object mLock = new Object();

    private int mIMServerPort = 8100;
    private int mOsnPort = 8400;
    private String mOsnConnector = null;
    private String mLogFileName = null;

    static class UserData{
        String userID;
        String userHash;
        SocketChannel socketChannel;
        SelectionKey key;
        long timelive;
    }

    private JSONObject errok(){return error("success");}
    private JSONObject error(String errCode){
        JSONObject json = new JSONObject();
        json.put("errCode", errCode);
        return json;
    }
    private JSONObject errFormat(){return error("error format");}
    private JSONObject errVerify(){return error("sign verify failed");}
    private JSONObject errUpdateDB(){return error("update db error");}
    private JSONObject errRight(){return error("no right");}
    private JSONObject errUser(){return error("no find user");}

    private Boolean isMember(GroupData group, String user){
        for(int i = 0; i < group.userList.size(); ++i){
            JSONObject json = group.userList.getJSONObject(i);
            if(json.getString("user").equalsIgnoreCase(user))
                return true;
        }
        return false;
    }
    private UserData getUserData(String userID, Boolean create){
        synchronized (mLock){
            UserData userData = null;
            if(create){
                userData = mUserMap.computeIfAbsent(userID, k -> new UserData());
                userData.userID = userID;
                userData.userHash = OsnUtils.getHash(userID);
                mUserMap.put(userData.userHash, userData);
            }
            else
                userData = mUserMap.get(userID);
            return userData;
        }
    }
    private JSONObject makeMessage(String command, String from, String to, JSONObject content, String privateKey){
        OsnUtils.logInfo("command = " + command + ", content = "+content.toString());
        String encData = ECUtils.ECEncrypt(to, content.toString().getBytes());
        String time = String.valueOf(System.currentTimeMillis());
        String data = from+to+encData+time;
        String hash = ECUtils.hashOsnData(data.getBytes());
        String sign = ECUtils.signOsnData(privateKey, data.getBytes());
        JSONObject json = new JSONObject();
        json.put("command", command);
        json.put("from", from);
        json.put("to", to);
        json.put("crypto", "yes");
        json.put("sign", sign);
        json.put("hash", hash);
        json.put("timestamp", time);
        json.put("content", encData);
        return json;
    }
    private Boolean checkMessage(JSONObject json){
        String from = json.getString("from");
        String to = json.getString("to");
        String content = json.getString("content");
        String time = json.getString("timestamp");
        if(from == null || to == null || content == null || time == null){
            OsnUtils.logInfo("same data miss");
            return false;
        }
        String data = from+to+content+time;
        String hash = ECUtils.hashOsnData(data.getBytes());
        if (hash.equalsIgnoreCase(json.getString("hash")) &&
                ECUtils.verifyOsnData(from, data.getBytes(), json.getString("sign")))
            return true;
        return false;
    }
    private JSONObject takeMessage(JSONObject json, String privateKey){
        try {
            String from = json.getString("from");
            String to = json.getString("to");
            String content = json.getString("content");
            String time = json.getString("timestamp");
            if(from == null || to == null || content == null || time == null){
                OsnUtils.logInfo("same data miss");
                return error("same data miss");
            }
            String data = from+to+content+time;
            String hash = ECUtils.hashOsnData(data.getBytes());
            if (hash.equalsIgnoreCase(json.getString("hash")) &&
                ECUtils.verifyOsnData(from, data.getBytes(), json.getString("sign"))) {
                byte[] rawData = ECUtils.ECDecrypt(privateKey, content);
                return JSONObject.parseObject(new String(rawData));
            }
            else {
                OsnUtils.logInfo("verify failed");
                return errVerify();
            }
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
            json = error(e.toString());
        }
        return json;
    }
    private void queneMessage(JSONObject json){
        try {
            String user = json.getString("to");
            UserData userData = getUserData(user, false);
            if(userData == null) {
                String toHash = OsnUtils.getHash(user);
                List<JSONObject> list = mHashMsg.computeIfAbsent(toHash, k -> new LinkedList<>());
                list.add(json);
                OsnUtils.logInfo("to: " + user);
                sendSocketJson(json);
            }
            else {
                sendChannelJson(userData.socketChannel, json);
            }
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
    }

    private void notifyUpdateGroup(GroupData group, JSONObject updateInfo){
        OsnUtils.logInfo("groupID = "+group.osnID+", updateList = "+updateInfo.toString());
        for(int i = 0; i < group.userList.size(); ++i) {
            JSONObject json = group.userList.getJSONObject(i);
            String user = json.getString("user");
            json = makeMessage("groupupdate", group.osnID, user, updateInfo, group.privateKey);
            queneMessage(json);
        }
    }
    private void distGroupMessage(JSONObject json, GroupData group){
        OsnUtils.logInfo("groupID = "+group.osnID);
        String content = json.getString("content");
        String from = json.getString("from");
        byte[] rawMsg = ECUtils.ECDecrypt(group.privateKey, content);
        for(int i = 0; i < group.userList.size(); ++i){
            JSONObject jsonUser = group.userList.getJSONObject(i);
            String user = jsonUser.getString("user");
            if(user.equalsIgnoreCase(from))
                continue;
            JSONObject jsonMsg = JSONObject.parseObject(new String(rawMsg));
            jsonMsg.put("from", from);
            jsonMsg = makeMessage("message", group.osnID, user, jsonMsg, group.privateKey);
            queneMessage(jsonMsg);
        }
    }
    private void clientMessage(JSONObject json){
        try {
            String user = json.getString("to");
            UserData userData = getUserData(user, false);
            if (userData == null)
                OsnUtils.logInfo("forward to no login user = " + user);
            else
                sendChannelJson(userData.socketChannel, json);
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
    }

    private JSONObject MsgComplete(JSONObject json){
        try {
            String from = json.getString("from");
            String to = json.getString("to");
            String hash = json.getString("hash");
            String sign = json.getString("sign");
            if(!ECUtils.verifyOsnHash(to, hash, sign)){
                OsnUtils.logInfo("verify error");
                return errVerify();
            }
            OsnUtils.logInfo("from: " + from + ", to: " + to);
            String toHash = OsnUtils.getHash(to);
            List<JSONObject> list = mHashMsg.get(toHash);
            if(list == null || list.size() == 0){
                OsnUtils.logInfo("no find data");
                return errok();
            }
//            Iterator<JSONObject> iterator = list.iterator();
//            while(iterator.hasNext()){
//                JSONObject jsonObject = iterator.next();
//                if(jsonObject.getString("hash").equalsIgnoreCase(hash)){
//                    if(jsonObject.containsKey("ip")){
//                        json.put("ip", jsonObject.getString("ip"));
//                        json = doPost(mOSNConnector, json);
//                    }
//                    else
//                        json = errok();
//                    iterator.remove();
//                    break;
//                }
//            }
            json = errok();
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
            json = error(e.toString());
        }
        return json;
    }
    private JSONObject GetMessage(JSONObject json){
        try {
            String userID = json.getString("user");
            if(userID == null){
                OsnUtils.logInfo(errFormat().toString());
                return errFormat();
            }
            UserData userData = getUserData(userID, false);
            if(userData == null && json.getString("ip") == null){
                OsnUtils.logInfo("user no login = "+userID);
                return errUser();
            }
            String userHash = OsnUtils.getHash(userID);
            JSONArray array = new JSONArray();
            if (mHashMsg.containsKey(userHash)) {
                List<JSONObject> list = mHashMsg.get(userHash);
                array.addAll(list);
                for (JSONObject o : list)
                    OsnUtils.logInfo("message = " + o.getString("command") + ", from = " + o.getString("from") + ", to = " + o.getString("to"));
                list.clear();
            }
            json = errok();
            json.put("data", array);
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
            json = error(e.toString());
        }
        return json;
    }
    private void RecvMessage(JSONObject json){
        try {
            String user = json.getString("to");
            if (ECUtils.isGroup(user)) {
                GroupData group = SqliteUtil.readGroup(user);
                if(group == null)
                    OsnUtils.logInfo("unknown group message = " + user);
                else
                    distGroupMessage(json, group);
            }
            else
                clientMessage(json);
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
    }
    private JSONObject SendMessage(JSONObject json){
        try {
            if(!checkMessage(json)){
                OsnUtils.logInfo("verify failed");
                return errVerify();
            }
            String user = json.getString("to");
            if(ECUtils.isGroup(user)){
                GroupData group = SqliteUtil.readGroup(user);
                if(group == null) {
                    OsnUtils.logInfo("forward group message osnID = " + user);
                    queneMessage(json);
                }
                else{
                    OsnUtils.logInfo("notify group message osnID = " + user);
                    distGroupMessage(json, group);
                }
            }
            else {
                OsnUtils.logInfo("user = " + json.getString("from") + ", to = " + user);
                queneMessage(json);
            }
            json = errok();
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
            json = error(e.toString());
        }
        return json;
    }
    private JSONObject FindUser(JSONObject json){
        try {
            String hash = json.getString("hash");
            String ip = json.getString("ip");

            OsnUtils.logInfo("ip: " + ip + ", hash: " + hash);
            if(ip == null){
                OsnUtils.logInfo("no ip");
                return null;
            }
            UserData userData = getUserData(hash, false);
            if (userData == null) {
                OsnUtils.logInfo("no login user/group, hash = " + hash);
                return null;
            }
            json = new JSONObject();
            json.put("command", "getmsg");
            json.put("user", userData.userID);
            return json;
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
        return null;
    }
    private void Heart(JSONObject json){
        try{
            String userID = json.getString("user");
            UserData userData = getUserData(userID, false);
            if(userData != null) {
                userData.timelive = System.currentTimeMillis();
                json = errok();
            }
            //OsnUtils.logInfo("userID = "+userID);
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
    }
    private JSONObject Login(JSONObject json, SocketChannel socketChannel, SelectionKey key){
        JSONObject result = null;
        try {
            String userID = json.getString("user");
            if (userID == null) {
                OsnUtils.logInfo(errFormat().toString());
                result = errFormat();
            }
            else {
                UserData userData = getUserData(userID, true);
                userData.socketChannel = socketChannel;
                userData.key = key;
                userData.timelive = System.currentTimeMillis();
                OsnUtils.logInfo("userID = " + userID);

                result = errok();
                result.put("serviceID", mServiceOsnID);
            }
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
            result = error(e.toString());
        }
        return result;
    }
    private JSONObject CreateGroup(JSONObject json){
        try {
            json = takeMessage(json, mServiceKey);
            if(json.containsKey("errCode"))
                return json;
            String groupID = json.getString("group");
            if (SqliteUtil.readGroup(groupID) != null) {
                OsnUtils.logInfo("groupID exist = " + groupID);
                return error("groupID exist");
            }
            String owner = json.getString("owner");
            GroupData group = new GroupData(groupID, json.getString("name"), json.getString("privateKey"),
                    json.getString("shadowKey"), json.getString("owner"), new JSONArray());
            OsnUtils.logInfo("groupID = " + json.getString("group") + ", owner = " + owner);
            if (SqliteUtil.insertGroup(group)) {
                getUserData(groupID, true);
                return errok();
            }
            json = errUpdateDB();
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
            json = error(e.toString());
        }
        return json;
    }
    private JSONObject AddMember(JSONObject json){
        try{
            String groupID = json.getString("to");
            GroupData group = SqliteUtil.readGroup(groupID);
            if(group == null){
                OsnUtils.logInfo("group no exist = " + groupID);
                if(!json.containsKey("ip")) {
                    queneMessage(json);
                    return null;
                }
                return error("group no exist");
            }
            JSONObject data = takeMessage(json, group.privateKey);
            if(data.containsKey("errCode"))
                return data;
            JSONArray userList = data.getJSONArray("userList");
            JSONArray addList = new JSONArray();
            for(int i = 0; i < userList.size(); ++i){
                boolean finded = false;
                JSONObject newJson = userList.getJSONObject(i);
                if(!newJson.containsKey("name") || !newJson.containsKey("user")) {
                    OsnUtils.logInfo("need name and user");
                    break;
                }
                for(int j = 0; j < group.userList.size(); ++j){
                    JSONObject oldJson = group.userList.getJSONObject(i);
                    if(newJson.getString("user").equalsIgnoreCase(oldJson.getString("user"))) {
                        finded = true;
                        break;
                    }
                }
                if(!finded)
                    addList.add(newJson);
            }
            OsnUtils.logInfo("groupID = "+group.osnID+", userList = "+addList.toString());
            group.userList.addAll(addList);
            if(SqliteUtil.writeGroup(group)){
                JSONObject jsonNotify = new JSONObject();
                jsonNotify.put("userList", group.userList);
                notifyUpdateGroup(group, jsonNotify);
                json = errok();
            }
            else
                json = errUpdateDB();
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
            json = error(e.toString());
        }
        return json;
    }
    private JSONObject GetGroupInfo(JSONObject json){
        String groupID = json.getString("to");
        String user = json.getString("from");
        OsnUtils.logInfo("group = "+groupID+", user = "+user);
        GroupData group = SqliteUtil.readGroup(groupID);
        if(group == null){
            OsnUtils.logInfo("group no find = "+groupID);
            if(!json.containsKey("ip"))
                queneMessage(json);
            return null;
        }
        if(!isMember(group, user)){
            OsnUtils.logInfo("user no in group = "+user);
            return errRight();
        }
        JSONObject data = group.toJson();
        json = makeMessage("groupinfo", group.osnID, user, data, group.privateKey);
        json.put("errCode", "success");
        return json;
    }
    private byte[] makePackage(JSONObject json){
        byte[] jsonData = json.toString().getBytes();
        byte[] data = new byte[jsonData.length+4];
        data[0] = (byte)((jsonData.length>>24)&0xff);
        data[1] = (byte)((jsonData.length>>16)&0xff);
        data[2] = (byte)((jsonData.length>>8)&0xff);
        data[3] = (byte)(jsonData.length&0xff);
        System.arraycopy(jsonData, 0, data, 4, jsonData.length);
        return data;
    }
    private void sendSocketJson(JSONObject json){
        try {
            OsnUtils.logInfo("command: " + json.getString("command"));
            byte[] data = makePackage(json);
            Socket socket = new Socket(mOsnConnector, mOsnPort);
            OutputStream outputStream = socket.getOutputStream();
            outputStream.write(data);
            socket.close();
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
    }
    private void sendChannelJson(SocketChannel socketChannel, JSONObject json){
        try {
            byte[] data = makePackage(json);
            ByteBuffer buffer = ByteBuffer.wrap(data);
            socketChannel.write(buffer);
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
    }
    private void handleMessage(SelectionKey key, String text){
        try {
            JSONObject json = JSONObject.parseObject(text);
            SocketChannel socketChannel = (SocketChannel)key.channel();

            JSONObject result = null;
            String command = json.getString("command");

            if("heart".equalsIgnoreCase(command))
                Heart(json);
            else if ("login".equalsIgnoreCase(command)) {
                result = Login(json, socketChannel, key);
                result.put("command", command);
            }
            else if("getmsg".equalsIgnoreCase(command)){
                result = GetMessage(json);
                result.put("command", "msglist");
            }
            else if("msglist".equalsIgnoreCase(command)){
                JSONArray array = json.getJSONArray("data");
                for(int i = 0; i < array.size(); ++i){
                    JSONObject msgData = array.getJSONObject(i);
                    command = msgData.getString("command");
                    switch(command){
                        //远端消息
                        case "message":
                            RecvMessage(msgData);
                            break;
                        case "groupupdate":
                            clientMessage(msgData);
                            break;

                        //远端命令
                        case "getgroupinfo":
                            result = GetGroupInfo(msgData);
                            if(result != null) {
                                result.put("ip", json.getString("ip"));
                                sendSocketJson(result);
                            }
                            break;
                    }
                }
                result = null;
            }
            else if("message".equalsIgnoreCase(command)) {
                result = SendMessage(json);
                result.put("command", "sendmsg");
            }
            else if("groupinfo".equalsIgnoreCase(command)){
                clientMessage(json);
            }
            else if("finduser".equalsIgnoreCase(command))
                result = FindUser(json);
            else if ("complete".equalsIgnoreCase(command))
                MsgComplete(json);
            else if("creategroup".equalsIgnoreCase(command)) {
                result = CreateGroup(json);
                result.put("command", command);
            }
            else if("addmember".equalsIgnoreCase(command)) {
                result = AddMember(json);
                if(result != null)
                    result.put("command", "addmember");
            }
            else if("getgroupinfo".equalsIgnoreCase(command)) {
                result = GetGroupInfo(json);
            }
            else{
                OsnUtils.logInfo("unknown command: " + command);
                result = error("unknown command: "+command);
            }
            if(result != null) {
                if (json.containsKey("ip")) {
                    result.put("ip", json.getString("ip"));
                    sendSocketJson(result);
                } else {
                    sendChannelJson(socketChannel, result);
                }
            }
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
    }
    private void handlePackage(SelectionKey key){
        try {
            int readLength = 0;
            SocketChannel socketChannel = (SocketChannel) key.channel();
            byte[] recv = new byte[4096];
            ByteBuffer buffer = ByteBuffer.wrap(recv);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            while(readLength >= 0) {
                while(true){
                    buffer.clear();
                    readLength = socketChannel.read(buffer);
                    if(readLength <= 0)
                        break;
                    baos.write(recv, 0, readLength);
                }
                if(baos.size() == 0)
                    break;
                byte[] data = baos.toByteArray();
                int length = ((data[0] & 0xff) << 24) | ((data[1] & 0xff) << 16) | ((data[2] & 0xff) << 8) | (data[3] & 0xff);
                if (length + 4 > data.length) {
                    OsnUtils.logInfo("package length error: " + String.valueOf(length) + ", data length: " + String.valueOf(data.length));
                    break;
                }
                baos.reset();
                baos.write(data, 4, length);
                handleMessage(key, baos.toString());
                baos.reset();
                baos.write(data, length+4, data.length-length-4);
            }
            if(readLength < 0){
                //OsnUtils.logInfo("client disconnect: " + socketChannel.toString());
                key.cancel();
                socketChannel.close();
            }
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }
    private void handleTimeout(){
        try {
            synchronized (mLock) {
                long timeNow = System.currentTimeMillis();
                ArrayList<UserData> removeList = new ArrayList<>();
                Iterator<Map.Entry<String, UserData>> iterator = mUserMap.entrySet().iterator();
                while (iterator.hasNext()) {
                    Map.Entry<String, UserData> entry = iterator.next();
                    UserData userData = entry.getValue();
                    if(userData.timelive > 0) {
                        long alive = timeNow - userData.timelive;
                        if (alive < 0 || alive > 60 * 1000)
                            removeList.add(userData);
                    }
                }
                for(UserData userData:removeList){
                    //OsnUtils.logInfo("client timeout: " + userData.socketChannel.toString());
                    userData.key.cancel();
                    userData.socketChannel.close();
                    mUserMap.remove(userData.userID);
                    mUserMap.remove(userData.userHash);
                }
            }
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
    }
    private void StartServer(){
        try {
            OsnUtils.mLogFileName = mLogFileName;
            SqliteUtil.initSqlite();

            String[] serviceOsnID = SqliteUtil.getServiceID();
            if(serviceOsnID == null) {
                serviceOsnID = ECUtils.createOsnID("service");
                SqliteUtil.setServiceID(serviceOsnID);
            }
            mServiceOsnID = serviceOsnID[0];
            mServiceKey = serviceOsnID[1];

            ArrayList<String> groupList = SqliteUtil.listGroup();
            for(String o:groupList)
                getUserData(o, true);

            Selector selector = Selector.open();
            ServerSocketChannel serverChannel0 = ServerSocketChannel.open();
            serverChannel0.socket().bind(new InetSocketAddress(mIMServerPort));
            serverChannel0.configureBlocking(false);
            serverChannel0.register(selector, SelectionKey.OP_ACCEPT);
            OsnUtils.logInfo("Start IMServer in port 8100/8200");
            while (true){
                if(selector.select(5000) == 0){
                    handleTimeout();
                    continue;
                }
                Iterator<SelectionKey> iterator = selector.selectedKeys().iterator();
                while (iterator.hasNext()){
                    SelectionKey key = iterator.next();
                    if (key.isAcceptable()) {
                        ServerSocketChannel socketChannel = (ServerSocketChannel) key.channel();
                        SocketChannel channel = socketChannel.accept();
                        channel.configureBlocking(false);
                        channel.register(selector, SelectionKey.OP_READ);
                        //OsnUtils.logInfo("client connect: " + channel.toString());
                    }
                    if (key.isReadable()) {
                        key.interestOps(key.interestOps()&~SelectionKey.OP_READ);
                        mExecutorService.submit(() -> {
                            handlePackage(key);
                            key.interestOps(key.interestOps()|SelectionKey.OP_READ);
                        });
                    }
                    if (key.isWritable()) {
                    }
                    iterator.remove();
                }
            }
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
    }
}
