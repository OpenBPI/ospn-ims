package com.ospn.utils;

import com.mchange.v2.c3p0.ComboPooledDataSource;
import com.ospn.Constant;
import com.ospn.common.ECUtils;
import com.ospn.data.*;

import javax.jws.soap.SOAPBinding;
import java.sql.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import static com.ospn.common.OsnUtils.logError;
import static com.ospn.common.OsnUtils.logInfo;

public class DBUtils {
    private static ComboPooledDataSource comboPooledDataSource = null;

    public void initDB(){
        comboPooledDataSource = new ComboPooledDataSource();
        try {
            String url01 = comboPooledDataSource.getJdbcUrl().substring(0,comboPooledDataSource.getJdbcUrl().indexOf("?"));
            String datasourceName = url01.substring(url01.lastIndexOf("/")+1);

            String jdbc = comboPooledDataSource.getJdbcUrl().replace(datasourceName, "");
            Connection connection = DriverManager.getConnection(jdbc, comboPooledDataSource.getUser(), comboPooledDataSource.getPassword());
            Statement statement = connection.createStatement();

            statement.executeUpdate("CREATE DATABASE IF NOT EXISTS `" + datasourceName + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;");

            statement.close();
            connection.close();

            createTable();
            updateTable();

        } catch (Exception e) {
            logError(e);
            System.exit(-1);
        }
    }
    private void createTable(){
        try {
            String[] sqls = {
                    "CREATE TABLE IF NOT EXISTS t_service " +
                            "(id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT, " +
                            " osnID char(128) NOT NULL, " +
                            " privateKey char(255) NOT NULL)",

                    "CREATE TABLE IF NOT EXISTS t_group " +
                            "(id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT, " +
                            " osnID char(128) NOT NULL UNIQUE, " +
                            " name text NOT NULL, " +
                            " owner char(128) NOT NULL, " +
                            " privateKey char(255) NOT NULL, " +
                            " portrait text not null, " +
                            " type tinyint default 0, " +
                            " joinType tinyint default 0, " +
                            " passType tinyint default 0, " +
                            " maxMember int default 200)",

                    "CREATE TABLE IF NOT EXISTS t_groupMember " +
                            "(id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT, " +
                            " osnID char(128) NOT NULL, " +
                            " groupID char(128) NOT NULL, " +
                            " remarks nvarchar(128), " + //add 2020.12.8
                            " nickName nvarchar(20), " + //add 2020.12.8
                            " type tinyint default 0, " +
                            " mute tinyint default 0, " +
                            " inviter char(128) NOT NULL, " +
                            " state tinyint default 0)",

                    "CREATE TABLE IF NOT EXISTS t_user " +
                            "(id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT, " +
                            " osnID char(128) NOT NULL UNIQUE, " +
                            " privateKey char(255) NOT NULL, " +
                            " name nvarchar(20) NOT NULL, " +
                            " displayName nvarchar(20) NOT NULL, " +
                            " nickName nvarchar(20), " + //add 2020.12.8
                            " aesKey char(64) NOT NULL, " +
                            " msgKey char(64) NOT NULL, " +
                            " maxGroup int default 100, " +
                            " portrait text, " +
                            " describes text, " + //add 2020.12.8
                            " password varchar(64) NOT NULL)",

                    "CREATE TABLE IF NOT EXISTS t_friend " +
                            "(id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT, " +
                            " osnID char(128) NOT NULL, " +
                            " friendID char(128) NOT NULL, " +
                            " remarks nvarchar(128), " + //add 2020.12.8
                            " state tinyint DEFAULT 0 )",

                    "CREATE TABLE IF NOT EXISTS t_message " +
                            "(id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT, " +
                            " cmd char(64) NOT NULL, " +
                            " fromID char(128) NOT NULL, " +
                            " toID char(128) NOT NULL, " +
                            " state tinyint DEFAULT 0, " +
                            " timeStamp bigint NOT NULL, " +
                            " hash char(128) NOT NULL, " +
                            " hash0 char(128), " +
                            " data text NOT NULL)",

                    "CREATE TABLE IF NOT EXISTS t_receipt " +
                            "(id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT, " +
                            " cmd char(64) NOT NULL, " +
                            " fromID char(128) NOT NULL, " +
                            " toID char(128) NOT NULL, " +
                            " state tinyint DEFAULT 0, " +
                            " timeStamp bigint NOT NULL, " +
                            " hash char(128) NOT NULL, " +
                            " hash0 char(128), " +
                            " data text NOT NULL)",

                    "CREATE TABLE IF NOT EXISTS t_conversation " +
                            "(id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT, " +
                            " userID char(128) NOT NULL, " +
                            " target char(128) NOT NULL, " +
                            " data text NOT NULL)",

                    "CREATE TABLE IF NOT EXISTS t_litapp " +
                            "(id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT, " +
                            " osnID char(128) NOT NULL UNIQUE, " +
                            " name nvarchar(20) NOT NULL, " +
                            " displayName nvarchar(20) NOT NULL, " +
                            " privateKey char(255) NOT NULL, " +
                            " portrait text, " +
                            " theme text, " +
                            " url text not null, " +
                            " info text, " +
                            " config text)",

                    "CREATE TABLE IF NOT EXISTS t_osnid " +
                            "(id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT, " +
                            " osnID char(128) NOT NULL UNIQUE, " +
                            " timeNewly bigint NOT NULL, " +
                            " timeChange bigint NOT NULL, " +
                            " tip char(32))",

                    "CREATE TABLE IF NOT EXISTS t_syncinfo " +
                            "(id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT, " +
                            " ip char(32) NOT NULL, " +
                            " timeNewly bigint NOT NULL, " +
                            " timeChange bigint NOT NULL)",
            };
            Connection connection = comboPooledDataSource.getConnection();
            Statement stmt = connection.createStatement();
            for(String sql : sqls)
                stmt.executeUpdate(sql);
            stmt.close();
            connection.close();
        }
        catch (Exception e){
            logError(e);
            System.exit(-1);
        }
    }
    private void updateTable() {
        try {
            String[] sqls = {
                    "alter table t_user add column urlSpace text not null", //add 2021.5.15
                    "alter table t_groupMember add column type tinyint default 0", //add 2021.5.20
                    "alter table t_groupMember add column mute tinyint default 0", //add 2021.5.21
                    "alter table t_group add column joinType tinyint default 0", //add 2021.5.21
                    "alter table t_group add column passType tinyint default 0", //add 2021.5.21
                    "alter table t_group add column mute tinyint default 0", //add 2021.5.21
                    "alter table t_group modify column name text not null", //add 2021.5.21
                    "alter table t_groupMember add column inviter char(128) NOT NULL", //add 2021.5.21
                    "alter table t_message add column hash0 char(128) not null",
                    "alter table t_receipt add column hash0 char(128) not null",
            };
            Connection connection = comboPooledDataSource.getConnection();
            Statement stmt = connection.createStatement();
            for(String sql : sqls) {
                try {
                    stmt.executeUpdate(sql);
                }
                catch (Exception e){
                    logError(e + ": " + sql);
                }
            }
            stmt.close();
            connection.close();
        }
        catch (Exception e){
            logError(e);
            System.exit(-1);
        }
    }

    private void closeDB(Connection connection, PreparedStatement statement, ResultSet rs){
        try{
            if(rs != null)
                rs.close();
        }
        catch (Exception e){
            logError(e);
        }
        try{
            if(statement != null)
                statement.close();
        }
        catch (Exception e){
            logError(e);
        }
        try{
            if(connection != null)
                connection.close();
        }
        catch (Exception e){
            logError(e);
        }
    }
    private UserData toUserData(ResultSet rs){
        try {
            UserData userData = new UserData();
            userData.osnID = rs.getString("osnID");
            userData.osnKey = rs.getString("privateKey");
            userData.name = rs.getString("name");
            userData.password = rs.getString("password");
            userData.displayName = rs.getString("displayName");
            userData.nickName = rs.getString("nickName");
            userData.describes = rs.getString("describes");
            userData.aesKey = rs.getString("aesKey");
            userData.msgKey = rs.getString("msgKey");
            userData.maxGroup = rs.getInt("maxGroup");
            userData.portrait = rs.getString("portrait");
            userData.urlSpace = rs.getString("urlSpace");
            return userData;
        }
        catch (Exception e){
            logError(e);
        }
        return null;
    }
    private GroupData toGroupData(ResultSet rs){
        try{
            GroupData groupData = new GroupData();
            groupData.osnID = rs.getString("osnID");
            groupData.name = rs.getString("name");
            groupData.owner = rs.getString("owner");
            groupData.type = rs.getInt("type");
            groupData.joinType = rs.getInt("joinType");
            groupData.passType = rs.getInt("passType");
            groupData.mute = rs.getInt("mute");
            groupData.osnKey = rs.getString("privateKey");
            groupData.portrait = rs.getString("portrait");
            groupData.maxMember = rs.getInt("maxMember");
            return groupData;
        }
        catch (Exception e){
            logError(e);
        }
        return null;
    }
    private FriendData toFriend(ResultSet rs){
        try {
            FriendData friendData = new FriendData();
            friendData.userID = rs.getString("osnID");
            friendData.friendID = rs.getString("friendID");
            friendData.remarks = rs.getString("remarks");
            friendData.state = rs.getInt("state");
            return friendData;
        }
        catch (Exception e){
            logError(e);
        }
        return null;
    }
    private MemberData toMemberData(ResultSet rs){
        try {
            MemberData memberData = new MemberData();
            memberData.osnID = rs.getString("osnID");
            memberData.groupID = rs.getString("groupID");
            memberData.remarks = rs.getString("remarks");
            memberData.nickName = rs.getString("nickName");
            memberData.inviter = rs.getString("inviter");
            memberData.type = rs.getInt("type");
            memberData.mute = rs.getInt("mute");
            return memberData;
        }
        catch (Exception e){
            logError(e);
        }
        return null;
    }
    private MessageData toMessageData(ResultSet rs){
        try {
            MessageData messageData = new MessageData();
            messageData.cmd = rs.getString("cmd");
            messageData.fromID = rs.getString("fromID");
            messageData.toID = rs.getString("toID");
            messageData.timeStamp = rs.getLong("timeStamp");
            messageData.data = rs.getString("data");
            messageData.hash = rs.getString("hash");
            messageData.hash0 = rs.getString("hash0");
            messageData.state = rs.getInt("state");
            return messageData;
        }
        catch (Exception e){
            logError(e);
        }
        return null;
    }
    private LitappData toLitappData(ResultSet rs){
        try {
            LitappData litappData = new LitappData();
            litappData.osnID = rs.getString("osnID");
            litappData.name = rs.getString("name");
            litappData.displayName = rs.getString("displayName");
            litappData.osnKey = rs.getString("privateKey");
            litappData.portrait = rs.getString("portrait");
            litappData.theme = rs.getString("theme");
            litappData.url = rs.getString("url");
            litappData.info = rs.getString("info");
            litappData.config = rs.getString("config");
            return litappData;
        }
        catch (Exception e){
            logError(e);
        }
        return null;
    }

    public CryptData getServiceID(){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        CryptData serviceData = null;
        try {
            String sql = "select * from t_service;";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            rs = statement.executeQuery();
            if(rs.next()){
                serviceData = new CryptData();
                serviceData.osnID = rs.getString("osnID");
                serviceData.osnKey = rs.getString("privateKey");
            }
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return serviceData;
    }
    public void setServiceID(CryptData serviceID){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "insert into t_service(osnID,privateKey) values(?,?)";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,serviceID.osnID);
            statement.setString(2,serviceID.osnKey);
            statement.executeUpdate();
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
    }

    public boolean insertGroup(GroupData group){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "insert into t_group(osnID,name,privateKey,owner,portrait) values(?,?,?,?,?)";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,group.osnID);
            statement.setString(2,group.name);
            statement.setString(3,group.osnKey);
            statement.setString(4,group.owner);
            statement.setString(5,group.portrait);
            int count = statement.executeUpdate();
            return count != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public GroupData readGroup(String groupID){
        GroupData group = null;
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "select * from t_group where osnID=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,groupID);
            rs = statement.executeQuery();
            if(rs.next())
                group = toGroupData(rs);
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return group;
    }
    public boolean updateGroup(GroupData groupData, List<String> keys){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            StringBuilder columns = new StringBuilder();
            for(String k:keys){
                if(columns.length() != 0)
                    columns.append(",");
                if(k.equalsIgnoreCase("name"))
                    columns.append("name=?");
                else if(k.equalsIgnoreCase("portrait"))
                    columns.append("portrait=?");
                else if(k.equalsIgnoreCase("type"))
                    columns.append("type=?");
                else if(k.equalsIgnoreCase("joinType"))
                    columns.append("joinType=?");
                else if(k.equalsIgnoreCase("passType"))
                    columns.append("passType=?");
                else if(k.equalsIgnoreCase("mute"))
                    columns.append("mute=?");
            }
            if(columns.length() == 0) {
                logInfo("key error");
                return false;
            }
            String sql = "update t_group set "+columns+" where osnID=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            int index = 1;
            for(String k:keys){
                if(k.equalsIgnoreCase("name"))
                    statement.setString(index++,groupData.name);
                else if(k.equalsIgnoreCase("portrait"))
                    statement.setString(index++,groupData.portrait);
                else if(k.equalsIgnoreCase("type"))
                    statement.setInt(index++,groupData.type);
                else if(k.equalsIgnoreCase("joinType"))
                    statement.setInt(index++,groupData.joinType);
                else if(k.equalsIgnoreCase("passType"))
                    statement.setInt(index++,groupData.passType);
                else if(k.equalsIgnoreCase("mute"))
                    statement.setInt(index++,groupData.mute);
            }
            statement.setString(index,groupData.osnID);
            int count = statement.executeUpdate();
            return count != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public boolean deleteGroup(GroupData group){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "delete from t_group where osnID=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,group.osnID);
            int count = statement.executeUpdate();
            return count != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public List<String> listGroup(String userID, boolean isAll){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        List<String> groupList = new ArrayList<>();
        try {
            String sql = isAll ? "select groupID from t_groupMember where osnID=?"
                               : "select groupID from t_groupMember where osnID=? and type<>0";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,userID);
            rs = statement.executeQuery();
            while(rs.next())
                groupList.add(rs.getString("groupID"));
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return groupList;
    }
    public List<GroupData> listGroup(String osnID, int limit){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        List<GroupData> groupList = new ArrayList<>();
        try {
            String sql = osnID == null
                    ? "select * from t_group where id>=0 limit ?"
                    : "select * from t_group where id>(select id from t_group where osnID=?) limit ?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            if(osnID == null){
                statement.setInt(1, limit);
            }
            else{
                statement.setString(1, osnID);
                statement.setInt(2, limit);
            }
            rs = statement.executeQuery();
            while(rs.next()){
                GroupData groupData = toGroupData(rs);
                groupList.add(groupData);
            }
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return groupList;
    }

    public boolean insertMember(MemberData memberData){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "insert into t_groupMember(osnID,groupID,type,inviter) values(?,?,?,?)";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,memberData.osnID);
            statement.setString(2,memberData.groupID);
            statement.setInt(3,memberData.type);
            statement.setString(4,memberData.inviter);
            int count = statement.executeUpdate();
            return count != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public boolean insertMembers(List<MemberData> members){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "insert into t_groupMember(osnID,groupID,type,inviter) values(?,?,?,?)";
            connection = comboPooledDataSource.getConnection();
            connection.setAutoCommit(false);
            statement = connection.prepareStatement(sql);
            for(MemberData memberData:members){
                statement.setString(1,memberData.osnID);
                statement.setString(2,memberData.groupID);
                statement.setInt(3,memberData.type);
                statement.setString(4,memberData.inviter);
                statement.addBatch();
            }
            int[] counts = statement.executeBatch();
            connection.commit();
            return counts.length != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public boolean updateMember(MemberData member, List<String> keys){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            StringBuilder columns = new StringBuilder();
            for(String k:keys){
                if(columns.length() != 0)
                    columns.append(",");
                if(k.equalsIgnoreCase("nickName"))
                    columns.append("nickName=?");
                else if(k.equalsIgnoreCase("remarks"))
                    columns.append("remarks=?");
                else if(k.equalsIgnoreCase("type"))
                    columns.append("type=?");
            }
            if(columns.length() == 0) {
                logInfo("key error");
                return false;
            }
            String sql = "update t_groupMember set "+columns+" where osnID=? and groupID=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            int index = 1;
            for(String k:keys){
                if(k.equalsIgnoreCase("nickName"))
                    statement.setString(index++,member.nickName);
                else if(k.equalsIgnoreCase("remarks"))
                    statement.setString(index++,member.remarks);
                else if(k.equalsIgnoreCase("type"))
                    statement.setInt(index++,member.type);
            }
            statement.setString(index++,member.osnID);
            statement.setString(index,member.groupID);
            int count = statement.executeUpdate();
            return count != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public boolean deleteMember(String userID, String groupID){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "delete from t_groupMember where osnID=? and groupID=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,userID);
            statement.setString(2,groupID);
            int count = statement.executeUpdate();
            return count != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public boolean deleteMembers(String groupID, List<String> members){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "delete from t_groupMember where osnID=? and groupID=?";
            connection = comboPooledDataSource.getConnection();
            connection.setAutoCommit(false);
            statement = connection.prepareStatement(sql);
            for(String member:members){
                statement.setString(1,member);
                statement.setString(2,groupID);
                statement.addBatch();
            }
            int[] counts = statement.executeBatch();
            connection.commit();
            return counts.length != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
	public List<MemberData> listMember(String groupID){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        List<MemberData> members = new ArrayList<>();
        try {
            String sql = "select * from t_groupMember where groupID=? and type<>0";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,groupID);
            rs = statement.executeQuery();
            while(rs.next())
                members.add(toMemberData(rs));
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return members;
    }
    public MemberData readMember(String groupID, String userID){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        MemberData memberData = null;
        try {
            String sql = "select * from t_groupMember where groupID=? and osnID=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,groupID);
            statement.setString(2,userID);
            rs = statement.executeQuery();
            if(rs.next())
                memberData = toMemberData(rs);
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return memberData;
    }

    public UserData readUserByName(String user){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        UserData userData = null;
        try {
            String sql = "select * from t_user where name=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,user);
            rs = statement.executeQuery();
            if(rs.next())
                userData = toUserData(rs);
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return userData;
    }
    public UserData readUserByID(String user){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        UserData userData = null;
        try {
            String sql = "select * from t_user where osnID=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,user);
            rs = statement.executeQuery();
            if(rs.next())
                userData = toUserData(rs);
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return userData;
    }

    public boolean insertUser(UserData userData){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "insert into t_user (osnID,privateKey,name,displayName,aesKey,msgKey,password,urlSpace) values(?,?,?,?,?,?,?,?)";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,userData.osnID);
            statement.setString(2,userData.osnKey);
            statement.setString(3,userData.name);
            statement.setString(4,userData.displayName);
            statement.setString(5,userData.aesKey);
            statement.setString(6,userData.msgKey);
            statement.setString(7,userData.password);
            statement.setString(8,userData.urlSpace);
            int count = statement.executeUpdate();
            //OsnUtils.logInfo(userData.osnID + ", name: "+userData.name);
            return count != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public boolean updateUser(UserData userData, List<String> keys){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            StringBuilder columns = new StringBuilder();
            for(String k:keys){
                if(columns.length() != 0)
                    columns.append(",");
                switch(k){
                    case "displayName":columns.append("displayName=?");break;
                    case "nickName":columns.append("nickName=?");break;
                    case "describes":columns.append("describes=?");break;
                    case "portrait":columns.append("portrait=?");break;
                    case "aesKey":columns.append("aesKey=?");break;
                    case "maxGroup":columns.append("maxGroup=?");break;
                    case "password":columns.append("password=?");break;
                    case "urlSpace":columns.append("urlSpace=?");break;
                }
            }
            if(columns.length() == 0){
                logInfo("key error");
                return false;
            }
            String sql = "update t_user set "+columns.toString()+" where osnID=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            int index = 1;
            for(String k:keys){
                switch(k){
                    case "displayName":statement.setString(index++,userData.displayName);break;
                    case "nickName":statement.setString(index++,userData.nickName);break;
                    case "describes":statement.setString(index++,userData.describes);break;
                    case "portrait":statement.setString(index++,userData.portrait);break;
                    case "aesKey":statement.setString(index++,userData.aesKey);break;
                    case "maxGroup":statement.setInt(index++,userData.maxGroup);break;
                    case "password":statement.setString(index++,userData.password);break;
                    case "urlSpace":statement.setString(index++,userData.urlSpace);break;
                }
            }
            statement.setString(index,userData.osnID);
            int count = statement.executeUpdate();
            return count != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public List<UserData> listUser(String osnID, int limit){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        List<UserData> userList = new ArrayList<>();
        try {
            String sql = osnID == null
                    ? "select * from t_user where id>=0 limit ?"
                    : "select * from t_user where id>(select id from t_user where osnID=?) limit ?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            if(osnID == null){
                statement.setInt(1, limit);
            }
            else{
                statement.setString(1, osnID);
                statement.setInt(2, limit);
            }
            rs = statement.executeQuery();
            while(rs.next()){
                UserData userData = toUserData(rs);
                userList.add(userData);
            }
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return userList;
    }

    public boolean insertFriend(FriendData friendData){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "insert into t_friend (osnID,friendID,state) values(?,?,?);";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,friendData.userID);
            statement.setString(2,friendData.friendID);
            statement.setInt(3,friendData.state);
            int count = statement.executeUpdate();
            return count != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public boolean updateFriend(FriendData friendData, List<String> keys){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            StringBuilder columns = new StringBuilder();
            for(String k:keys){
                if(columns.length() != 0)
                    columns.append(",");
                switch(k){
                    case "remarks":columns.append("remarks=?");break;
                    case "state":columns.append("state=?");break;
                }
            }
            if(columns.length() == 0){
                logInfo("key error");
                return false;
            }
            String sql = "update t_friend set "+columns.toString()+" where osnID=? and friendID=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            int index = 1;
            for(String k:keys){
                switch(k){
                    case "remarks":statement.setString(index++, friendData.remarks);break;
                    case "state":statement.setInt(index++,friendData.state);break;
                }
            }
            statement.setString(index++,friendData.userID);
            statement.setString(index,friendData.friendID);
            int count = statement.executeUpdate();
            return count != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public FriendData readFriend(String userID, String friendID){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "select * from t_friend where osnID=? and friendID=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,userID);
            statement.setString(2,friendID);
            rs = statement.executeQuery();
            if(rs.next())
                return toFriend(rs);
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return null;
    }
    public List<FriendData> listFriend(String userID){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
		List<FriendData> friendList = new ArrayList<>();
        try {
            String sql = "select * from t_friend where osnID=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,userID);
            rs = statement.executeQuery();
            while(rs.next())
                friendList.add(toFriend(rs));
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return friendList;
    }
    public boolean deleteFriend(String userID, String friendID){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "delete from t_friend where osnID=? and friendID=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,userID);
            statement.setString(2,friendID);
            int count = statement.executeUpdate();
            return count != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }

    public boolean insertMessage(MessageData messageData){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            logInfo("cmd: "+messageData.cmd);
            String sql = "insert into t_message (fromID,toID,data,timeStamp,hash,hash0,state,cmd) values(?,?,?,?,?,?,?,?);";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,messageData.fromID);
            statement.setString(2,messageData.toID);
            statement.setString(3,messageData.data);
            statement.setLong(4,messageData.timeStamp);
            statement.setString(5,messageData.hash);
            statement.setString(6,messageData.hash0);
            statement.setInt(7,messageData.state);
            statement.setString(8,messageData.cmd);
            int count = statement.executeUpdate();
            return count != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public boolean updateMessage(MessageData messageData){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "update t_message set state=? where hash=? and fromID=? and toID=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setInt(1,messageData.state);
            statement.setString(2,messageData.hash);
            statement.setString(3,messageData.fromID);
            statement.setString(4,messageData.toID);
            int count = statement.executeUpdate();
            return count != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public boolean deleteMessage(String hash){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "delete from t_message where hash=? or hash0=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,hash);
            statement.setString(2,hash);
            int count = statement.executeUpdate();
            return count != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public List<MessageData> syncMessages(String userID, long timestamp, int count){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
		List<MessageData> messageDataList = new ArrayList<>();
        try {
            String sql = "select * from (select * from t_message where timeStamp>?) tmp where toID=? limit ?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setLong(1,timestamp);
            statement.setString(2,userID);
            statement.setInt(3,count);
            rs = statement.executeQuery();
            while(rs.next()){
                MessageData messageData = toMessageData(rs);
                if(messageData != null)
                    messageDataList.add(messageData);
            }
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return messageDataList;
    }
    public List<MessageData> loadMessages(String userID, String target, long timestamp, boolean before, int count){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        List<MessageData> messageDataList = new ArrayList<>();
        try {
            String sql = before
                    ? "select * from (select * from t_message where cmd='Message' and timeStamp<? and (fromID=? and toID=? or fromID=? and toID=?) order by timeStamp desc limit ?) tmp order by timeStamp"
                    : "select * from t_message where cmd='Message' and timeStamp>? and (fromID=? and toID=? or fromID=? and toID=?) limit ?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setLong(1,timestamp);
            statement.setString(2,userID);
            statement.setString(3,target);
            statement.setString(4,target);
            statement.setString(5,userID);
            statement.setInt(6,count);
            rs = statement.executeQuery();
            while(rs.next()){
                MessageData messageData = toMessageData(rs);
                if(messageData != null)
                    messageDataList.add(messageData);
            }
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return messageDataList;
    }
    public List<MessageData> loadRequest(String userID, long timeStamp, int count){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        List<MessageData> requestList = new ArrayList<>();
        try {
            String sql = "select * from (select * from t_message where cmd='AddFriend' and toID=? and timeStamp<? order by timeStamp desc limit ?) tmp order by timeStamp";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,userID);
            statement.setLong(2,timeStamp);
            statement.setInt(3,count);
            rs = statement.executeQuery();
            while(rs.next())
                requestList.add(toMessageData(rs));
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return requestList;
    }
    public boolean updateRequest(String userID, String friendID, String cmd, int state){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "update t_message set state=? where cmd=? and toID=? and fromID=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setInt(1,state);
            statement.setString(2,cmd);
            statement.setString(3,userID);
            statement.setString(4,friendID);
            int count = statement.executeUpdate();
            return count != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public MessageData queryMessage(String hash){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        MessageData messageData = null;
        try {
            String sql = "select * from t_message where hash='?'";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,hash);
            rs = statement.executeQuery();
            if(rs.next())
                messageData = toMessageData(rs);
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return messageData;
    }

    public boolean insertReceipt(MessageData messageData){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "insert into t_receipt (fromID,toID,data,timeStamp,hash,hash0,state,cmd) values(?,?,?,?,?,?,?,?);";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,messageData.fromID);
            statement.setString(2,messageData.toID);
            statement.setString(3,messageData.data);
            statement.setLong(4,messageData.timeStamp);
            statement.setString(5,messageData.hash);
            statement.setString(6,messageData.hash0);
            statement.setInt(7,messageData.state);
            statement.setString(8,messageData.cmd);
            int count = statement.executeUpdate();
            return count != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public boolean updateReceipt(String hash, int state){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "update t_receipt set state=? where hash=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setInt(1,state);
            statement.setString(2,hash);
            int count = statement.executeUpdate();
            return count != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public MessageData queryReceipt(String hash){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "select * from t_receipt where hash=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,hash);
            rs = statement.executeQuery();
            if(rs.next())
                return toMessageData(rs);
            return null;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return null;
    }
    public List<MessageData> queryReceipts(){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
		List<MessageData> messageDataList = new ArrayList<>();
        try {
            String sql = "select * from t_receipt where state=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setInt(1, Constant.ReceiptStatus_Wait);
            rs = statement.executeQuery();
            while(rs.next()){
                MessageData messageData = toMessageData(rs);
                if(messageData != null)
                    messageDataList.add(messageData);
            }
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return messageDataList;
    }
    public void clearReceipts(){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "update t_receipt set state=?"+" where state=0";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setInt(1, Constant.ReceiptStatus_Error);
            statement.executeUpdate();
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
    }

    public List<String> listConversation(String userID){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        List<String> conversationList = new ArrayList<>();
        try {
            String sql = "select target from t_conversation where userID=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,userID);
            rs = statement.executeQuery();
            while(rs.next())
                conversationList.add(rs.getString("target"));
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return conversationList;
    }
    public boolean setConversationInfo(String userID, String target, String data){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "replace into t_conversation (userID,target,data) values(?,?,?)";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,userID);
            statement.setString(2,target);
            statement.setString(3,data);
            int count = statement.executeUpdate();
            return count != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public String getConversationInfo(String userID, String target){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "select data from t_conversation where userID=? and target=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1, userID);
            statement.setString(2, target);
            rs = statement.executeQuery();
            if(rs.next())
                return rs.getString("data");
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return null;
    }
    public boolean delConversationInfo(String userID, String target){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "delete from t_conversation where userID=? and target=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,userID);
            statement.setString(2,target);
            int count = statement.executeUpdate();
            return count != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }

    public boolean insertLitapp(LitappData litappData){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            if(litappData.name.length() >= 20)
                litappData.name = litappData.name.substring(0,19);

            String sql = "replace into t_litapp(osnID,name,displayName,privateKey,portrait,theme,url,info,config) values(?,?,?,?,?,?,?,?,?)";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,litappData.osnID);
            statement.setString(2,litappData.name);
            statement.setString(3,litappData.displayName);
            statement.setString(4,litappData.osnKey);
            statement.setString(5,litappData.portrait);
            statement.setString(6,litappData.theme);
            statement.setString(7,litappData.url);
            statement.setString(8,litappData.info);
            statement.setString(9,litappData.config);
            int count = statement.executeUpdate();
            return count != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public boolean deleteLitapp(String osnID){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "delete from t_litapp where osnID=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,osnID);
            int count = statement.executeUpdate();
            return count != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public List<LitappData> listLitapp(){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        List<LitappData> litappDataList = new ArrayList<>();
        try {
            String sql = "select * from t_litapp";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            rs = statement.executeQuery();
            while(rs.next()){
                LitappData litappData = toLitappData(rs);
                if(litappData != null)
                    litappDataList.add(litappData);
            }
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return litappDataList;
    }
    public LitappData readLitapp(String osnID){
        LitappData litappData = null;
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "select * from t_litapp where osnID=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,osnID);
            rs = statement.executeQuery();
            if(rs.next())
                litappData = toLitappData(rs);
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return litappData;
    }

    public boolean isRegisterName(String name){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "select count(*) from t_user where name=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,name);
            rs = statement.executeQuery();
            if(rs.next())
                return rs.getInt(1) != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public boolean isRegisterUser(String user){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "select count(*) from t_user where osnID=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,user);
            rs = statement.executeQuery();
            if(rs.next())
                return rs.getInt(1) != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public boolean isMyGroup(String osnID){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "select count(*) from t_group where osnID=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,osnID);
            rs = statement.executeQuery();
            if(rs.next())
                return rs.getInt(1) != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public boolean isMember(String userID, String groupID){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "select count(*) from t_groupMember where osnID=? and groupID=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,userID);
            statement.setString(2,groupID);
            rs = statement.executeQuery();
            if(rs.next())
                return rs.getInt(1) != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
    public boolean isFriend(String userID, String friendID){
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            String sql = "select count(*) from t_friend where osnID=? and friendID=?";
            connection = comboPooledDataSource.getConnection();
            statement = connection.prepareStatement(sql);
            statement.setString(1,userID);
            statement.setString(2,friendID);
            rs = statement.executeQuery();
            if(rs.next())
                return rs.getInt(1) != 0;
        }
        catch (Exception e){
            logError(e);
        }
        finally {
            closeDB(connection,statement,rs);
        }
        return false;
    }
}
