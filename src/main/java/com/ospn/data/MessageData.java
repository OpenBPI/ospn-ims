package com.ospn.data;

import com.alibaba.fastjson.JSONObject;

public class MessageData {
    public String cmd;
    public String fromID;
    public String toID;
    public String data;
    public String hash;
    public String hash0;
    public long timeStamp;
    public int state;

    public static MessageData toMessageData(JSONObject json, int state){
        MessageData messageData = new MessageData();
        messageData.cmd = json.getString("command");
        messageData.fromID = json.getString("from");
        messageData.toID = json.getString("to");
        messageData.data = json.toString();
        messageData.hash = json.getString("hash");
        messageData.hash0 = json.containsKey("hash0") ? json.getString("hash0") : "";
        messageData.timeStamp = Long.parseLong(json.getString("timestamp"));
        messageData.state = state;
        return messageData;
    }
}
