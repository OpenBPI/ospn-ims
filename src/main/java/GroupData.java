import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

public class GroupData {
    public String osnID;
    public String name;
    public String privateKey;
    public String shadowKey;
    public String owner;
    public JSONArray userList;

    GroupData(String OsnID, String Name, String PrivateKey, String ShadowKey, String Owner, JSONArray UserList){
        this.osnID = OsnID;
        this.name = Name;
        this.privateKey = PrivateKey;
        this.shadowKey = ShadowKey;
        this.owner = Owner;
        this.userList = UserList;
    }
    JSONObject toJson(){
        JSONObject json = new JSONObject();
        json.put("group", osnID);
        json.put("name", name);
        json.put("privateKey", "");
        json.put("shadowKey", shadowKey);
        json.put("owner", owner);
        json.put("userList", userList);
        return json;
    }
}
