package com.ospn.data;

import com.alibaba.fastjson.JSONObject;

import java.util.List;

public class MemberData {
    public String osnID;
    public String groupID;
    public String remarks;
    public String nickName;
    public int type;
    public int mute;

    public String inviter;

    public static int MemberType_Wait = 0;
    public static int MemberType_Normal = 1;
    public static int MemberType_Owner = 2;
    public static int MemberType_Admin = 3;
    public static int MemberType_Deleted = -1;

    public MemberData(){}
    public MemberData(String osnID, String groupID, int type){
        this.osnID = osnID;
        this.groupID = groupID;
        this.type = type;
        this.inviter = "";
    }
    public MemberData(String osnID, String groupID, int type, String inviter){
        this.osnID = osnID;
        this.groupID = groupID;
        this.type = type;
        this.inviter = inviter;
    }
    public void update(MemberData memberData, List<String> keys){
        //目前member信息不放内存，此接口不需要
        for(String k : keys){
            if(k.equalsIgnoreCase("nickName"))
                nickName = memberData.nickName;
            else if(k.equalsIgnoreCase("remarks"))
                remarks = memberData.remarks;
            else if(k.equalsIgnoreCase("type"))
                type = memberData.type;
            else if(k.equalsIgnoreCase("mute"))
                mute = memberData.mute;
        }
    }
    public JSONObject toJson(){
        JSONObject json = new JSONObject();
        json.put("osnID",this.osnID);
        json.put("groupID",this.groupID);
        json.put("remarks",this.remarks);
        json.put("nickName",this.nickName);
        json.put("type",this.type);
        json.put("mute",this.mute);
        return json;
    }
    public boolean isAdmin(){
        return type == MemberType_Owner || type == MemberType_Admin;
    }
    public boolean isOwner(){
        return type == MemberType_Owner;
    }
}
