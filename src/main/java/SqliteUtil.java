import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class SqliteUtil {
    static Connection mConnect = null;

    private static void createServiceOsnIDTable(){
        try {
            Statement stmt = mConnect.createStatement();
            String sql = "CREATE TABLE serviceOsnID " +
                        "(OsnID TEXT PRIMARY KEY   NOT NULL, " +
                        " PrivateKey     TEXT    NOT NULL)";
            stmt.executeUpdate(sql);
            stmt.close();
        }
        catch (Exception e){
            LogFile.logInfo("createServiceOsnIDTable:" + e.getMessage());
        }
    }
    private static void createGroupOsnIDTable(){
        try {
            Statement stmt = mConnect.createStatement();
            String sql = "CREATE TABLE groupOsnID " +
                        "(OsnID TEXT PRIMARY KEY   NOT NULL, " +
                        " PrivateKey     TEXT    NOT NULL, " +
                        " ShadowKey      TEXT    NOT NULL, " +
                        " Owner          TEXT    NOT NULL, " +
                        " UserList       TEXT    NOT NULL)";
            stmt.executeUpdate(sql);
            stmt.close();
        }
        catch (Exception e){
            LogFile.logInfo("createGroupOsnIDTable:" + e.getMessage());
        }
    }
    public static void initSqlite(){
        try {
            Class.forName("org.sqlite.JDBC");
            mConnect = DriverManager.getConnection("jdbc:sqlite:test.db");
            createServiceOsnIDTable();
            createGroupOsnIDTable();

        } catch ( Exception e ) {
            LogFile.logInfo("initSqlite:"+e.getMessage());
        }
    }
    public static String[] getServiceID(){
        try {
            Statement stmt = mConnect.createStatement();
            ResultSet rs = stmt.executeQuery( "SELECT * FROM serviceOsnID;" );
            if(rs.next())
                return new String[]{rs.getString("OsnID"), rs.getString("PrivateKey")};
        }
        catch (Exception e){
            LogFile.logInfo("getServiceID:"+e.getMessage());
        }
        return null;
    }
    public static void setServiceID(String[] osnID){
        try {
            Statement stmt = mConnect.createStatement();
            String sql = "INSERT INTO serviceOsnID (OsnID,PrivateKey) " +
                    "VALUES ('" + osnID[0] + "', '"+ osnID[1] + "');";
            stmt.executeUpdate(sql);
            stmt.close();
        }
        catch (Exception e){
            LogFile.logInfo("setServiceID:" + e.getMessage());
        }
    }
    public static boolean insertGroup(JSONObject json){
        try {
            Statement stmt = mConnect.createStatement();
            String sql = "INSERT INTO groupOsnID (OsnID,PrivateKey,ShadowKey,Owner,UserList) " +
                    "VALUES ('" + json.getString("groupID") + "', '" +
                    json.getString("privaKey") + "','" +
                    json.getString("shadowKey") + "','" +
                    json.getString("owner") + "','"+
                    "'')";
            int count = stmt.executeUpdate(sql);
            stmt.close();
            LogFile.logInfo("insertGroup: " + json.getString("groupID")+ ", owner: "+json.getString("owner"));
            return count != 0;
        }
        catch (Exception e){
            LogFile.logInfo("insertGroup: " + e.getMessage());
        }
        return false;
    }
    public static JSONObject readGroup(String groupID){
        JSONObject json = null;
        try {
            Statement stmt = mConnect.createStatement();
            String sql = "select * from groupOsnID where OsnID="+groupID;
            ResultSet rs = stmt.executeQuery(sql);
            if(rs.next()){
                json = new JSONObject();
                json.put("OsnID", rs.getString("OsnID"));
                json.put("PrivateKey", rs.getString("PrivateKey"));
                json.put("ShadowKey", rs.getString("ShadowKey"));
                json.put("Owner", rs.getString("Owner"));
                json.put("UserList", rs.getString("UserList"));
            }
            stmt.close();
        }
        catch (Exception e){
            LogFile.logInfo("readGroup: " + e.getMessage());
        }
        return json;
    }
}
