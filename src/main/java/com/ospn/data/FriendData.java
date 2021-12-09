package com.ospn.data;

import com.alibaba.fastjson.JSONObject;

public class FriendData {
    public String userID;
    public String friendID;
    public String remarks;
    public int state;

    public static int FriendStatus_Wait = 0;
    public static int FriendStatus_Normal = 1;
    public static int FriendStatus_Delete = 2;
    public static int FriendStatus_Blacked = 3;


    public FriendData(){}
    public FriendData(String userID, String friendID, int state){
        this.userID = userID;
        this.friendID = friendID;
        this.state = state;
    }
    public JSONObject toJson(){
        JSONObject json = new JSONObject();
        json.put("userID", userID);
        json.put("friendID", friendID);
        json.put("remarks", remarks);
        json.put("state", state);
        return json;
    }
}
