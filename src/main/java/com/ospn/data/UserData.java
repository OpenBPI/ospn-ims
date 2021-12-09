package com.ospn.data;

import com.alibaba.fastjson.JSONObject;
import com.ospn.core.IMData;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static com.ospn.Constant.E_dataBase;
import static com.ospn.core.IMData.db;

public class UserData extends CryptData{
    public String name;
    public String password;
    public String displayName;
    public String nickName;
    public String describes;
    public String portrait;
    public String aesKey;
    public String msgKey;
    public int maxGroup;
    public String urlSpace;

    public SessionData session = null;
    public Set<String> friends = new HashSet<>();
    public Set<String> groups = new HashSet<>();
    public Set<String> blacked = new HashSet<>();

    public JSONObject toJson(){
        JSONObject json = new JSONObject();
        json.put("userID", osnID);
        json.put("name", name);
        json.put("displayName", displayName);
        json.put("nickName", nickName);
        json.put("describes", describes);
        json.put("portrait", portrait);
        json.put("urlSpace",urlSpace);
        return json;
    }
    public boolean isRelated(String osnID){
        if(osnID.startsWith("OSNG"))
            return groups.contains(osnID);
        return friends.contains(osnID);
    }
    public boolean isFriend(String osnID){
        return friends.contains(osnID);
    }
    public boolean isBlacked(String osnID){
        return blacked.contains(osnID);
    }
    public void addFriend(String friendID){
        friends.add(friendID);
    }
    public void delFriend(String friendID){
        friends.remove(friendID);
    }
    public void addBlack(String friendID){
        blacked.add(friendID);
    }
    public void delBlack(String friendID){
        blacked.remove(friendID);
    }
    public void addGroup(String groupID){
        groups.add(groupID);
    }
    public void delGroup(String groupID){
        groups.remove(groupID);
    }
    public boolean hasGroup(String groupID){
        return groups.contains(groupID);
    }

    public void updateKeys(List<String> keys, UserData userData){
        for(String key : keys){
            switch(key){
                case "displayName":
                    this.displayName = userData.displayName;
                    break;
                case "portrait":
                    this.portrait = userData.portrait;
                    break;
                case "nickName":
                    this.nickName = userData.nickName;
                    break;
                case "describes":
                    this.describes = userData.describes;
                    break;
                case "urlSpace":
                    this.urlSpace = userData.urlSpace;
                    break;
            }
        }
    }
    public List<String> parseKeys(JSONObject data, UserData userData){
        List<String> keys = new ArrayList<>();
        if (data.containsKey("displayName")) {
            this.displayName = data.getString("displayName");
            userData.displayName = this.displayName;
            keys.add("displayName");
        }
        if (data.containsKey("portrait")) {
            this.portrait = data.getString("portrait");
            userData.portrait = this.portrait;
            keys.add("portrait");
        }
        if (data.containsKey("nickName")) {
            this.nickName = data.getString("nickName");
            userData.nickName = this.nickName;
            keys.add("nickName");
        }
        if (data.containsKey("describes")) {
            this.describes = data.getString("describes");
            userData.describes = this.describes;
            keys.add("describe");
        }
        if (data.containsKey("urlSpace")) {
            this.urlSpace = data.getString("urlSpace");
            userData.urlSpace = this.urlSpace;
            keys.add("urlSpace");
        }
        return keys;
    }
}
