import com.alibaba.fastjson.JSONArray;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;

public class SqliteUtil {
    static Connection mConnect = null;

    private static void createServiceOsnIDTable(){
        try {
            Statement stmt = mConnect.createStatement();
            String sql = "CREATE TABLE serviceOsnID " +
                        "(osnID char(160) PRIMARY KEY   NOT NULL, " +
                        " privateKey     char(160)    NOT NULL)";
            stmt.executeUpdate(sql);
            stmt.close();
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
    }
    private static void createGroupOsnIDTable(){
        try {
            Statement stmt = mConnect.createStatement();
            String sql = "CREATE TABLE groupOsnID " +
                        "(osnID char(160) PRIMARY KEY   NOT NULL, " +
                        " name           nvarchar(20)    NOT NULL, " +
                        " owner          char(160)    NOT NULL, " +
                        " privateKey     char(160)    NOT NULL, " +
                        " shadowKey      char(160)    NOT NULL, " +
                        " userList       TEXT    NOT NULL)";
            stmt.executeUpdate(sql);
            stmt.close();
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
    }
    public static void initSqlite(){
        try {
            Class.forName("org.sqlite.JDBC");
            mConnect = DriverManager.getConnection("jdbc:sqlite:test.db");
            createServiceOsnIDTable();
            createGroupOsnIDTable();

        } catch ( Exception e ) {
            OsnUtils.logInfo(e.toString());
        }
    }
    public static String[] getServiceID(){
        try {
            Statement stmt = mConnect.createStatement();
            ResultSet rs = stmt.executeQuery( "SELECT * FROM serviceOsnID;" );
            if(rs.next())
                return new String[]{rs.getString("osnID"), rs.getString("privateKey")};
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
        return null;
    }
    public static void setServiceID(String[] osnID){
        try {
            Statement stmt = mConnect.createStatement();
            String sql = "INSERT INTO serviceOsnID (osnID,privateKey) " +
                    "VALUES ('" + osnID[0] + "', '"+ osnID[1] + "');";
            stmt.executeUpdate(sql);
            stmt.close();
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
    }
    public static boolean insertGroup(GroupData group){
        try {
            Statement stmt = mConnect.createStatement();
            String sql = "INSERT INTO groupOsnID (osnID,Name,privateKey,shadowKey,owner,userList) " +
                    "VALUES ('" +
                    group.osnID + "', '" +
                    group.name + "', '" +
                    group.privateKey + "','" +
                    group.shadowKey + "','" +
                    group.owner + "','" +
                    group.userList.toString() + "');";
            int count = stmt.executeUpdate(sql);
            stmt.close();
            OsnUtils.logInfo(group.osnID+ ", owner: "+group.owner);
            return count != 0;
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
        return false;
    }
    public static GroupData readGroup(String groupID){
        GroupData group = null;
        try {
            Statement stmt = mConnect.createStatement();
            String sql = "select * from groupOsnID where osnID='"+groupID+"';";
            ResultSet rs = stmt.executeQuery(sql);
            if(rs.next()){
                String userList = rs.getString("userList");
                JSONArray jsonArray = JSONArray.parseArray(userList);
                group = new GroupData(rs.getString("osnID"),
                        rs.getString("name"),
                        rs.getString("privateKey"),
                        rs.getString("shadowKey"),
                        rs.getString("owner"),
                        jsonArray);
            }
            stmt.close();
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
        return group;
    }
    public static boolean writeGroup(GroupData group){
        try{
            Statement stmt = mConnect.createStatement();
            String sql = "update groupOsnID set userList='"+group.userList +
                    "' where osnID='"+group.osnID+"';";
            stmt.executeUpdate(sql);
            stmt.close();
            return true;
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
        return false;
    }
    public static ArrayList<String> listGroup(){
        ArrayList<String> groupList = new ArrayList<String>();
        try {
            Statement stmt = mConnect.createStatement();
            String sql = "select * from groupOsnID;";
            ResultSet rs = stmt.executeQuery(sql);
            while(rs.next())
                groupList.add(rs.getString("osnID"));
            stmt.close();
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
        return groupList;
    }
}
