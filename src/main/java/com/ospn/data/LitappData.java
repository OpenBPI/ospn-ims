package com.ospn.data;

import com.alibaba.fastjson.JSONObject;

public class LitappData extends CryptData{
    public String name;
    public String displayName;
    public String portrait;
    public String theme;
    public String url;
    public String info;
    public String config;

    public JSONObject toJson(){
        JSONObject json = new JSONObject();
        json.put("type","Litapp");
        json.put("name", name);
        json.put("target", osnID);
        json.put("displayName", displayName);
        json.put("portrait", portrait);
        json.put("theme", theme);
        json.put("url", url);
        json.put("info", info);
        return json;
    }
    public static LitappData toObject(JSONObject json){
        LitappData litappData = new LitappData();
        litappData.osnID = json.getString("osnID");
        litappData.osnKey = json.getString("osnKey");
        litappData.name = json.getString("name");
        litappData.displayName = json.getString("displayName");
        litappData.portrait = json.getString("portrait");
        litappData.theme = json.getString("theme");
        litappData.url = json.getString("url");
        litappData.info = json.getString("info");
        return litappData;
    }
}
