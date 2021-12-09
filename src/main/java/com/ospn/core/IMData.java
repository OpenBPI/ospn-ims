package com.ospn.core;

import com.alibaba.fastjson.JSONObject;
import com.ospn.Constant;
import com.ospn.common.ECUtils;
import com.ospn.common.OsnUtils;
import com.ospn.data.*;
import com.ospn.utils.DBUtils;
import io.netty.channel.ChannelHandlerContext;

import java.io.FileInputStream;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import static com.ospn.common.OsnUtils.logError;
import static com.ospn.common.OsnUtils.logInfo;
import static com.ospn.data.FriendData.FriendStatus_Blacked;
import static com.ospn.data.MemberData.MemberType_Wait;

public class IMData {
    public static final ConcurrentHashMap<String, CommandData> cmdMap = new ConcurrentHashMap<>();
    public static final ConcurrentHashMap<String, UserData> userMap = new ConcurrentHashMap<>();           //userID to UserData
    public static final ConcurrentHashMap<ChannelHandlerContext, SessionData> sessionMap = new ConcurrentHashMap<>();
    public static final ConcurrentHashMap<String, GroupData> groupMap = new ConcurrentHashMap<>();
    public static final ConcurrentHashMap<String, LitappData> litappMap = new ConcurrentHashMap<>();
    public static final Set<String> cmdForward = new HashSet<>();
    public static final Object userLock = new Object();
    public static Properties prop = null;
    public static DBUtils db = null;
    public static CryptData service;
    public static String ipIMServer = null;
    public static String ipConnector = null;
    public static String urlSpace = null;
    public static boolean msgDelete = true;
    public static boolean standAlone = false;
    public static boolean needRelated = true;
    public static boolean autoFriendInternal = false;
    public static boolean autoFriendExternal = false;
    public static boolean appRegisterUser = true;
    public static int imServicePort = 8100;
    public static int imNotifyPort = 8200;
    public static int imAdminPort = 8300;
    public static int ospnServicePort = 8400;
    public static int imWebsockPort = 8700;
    public static int imHttpPort = 8800;
    public static int helpIn = 0;
    public static int helpOut = 0;
    public static String currentDay = null;
    public static String configFile = "ospn.properties";

    public static void init(){
        try {
            prop = new Properties();
            prop.load(new FileInputStream(configFile));
            db = new DBUtils();
            db.initDB();

            ipIMServer = prop.getProperty("ipIMServer");
            ipConnector = prop.getProperty("ipConnector");
            logInfo("Connector: " + ipConnector);

            imServicePort = Integer.parseInt(prop.getProperty("imServicePort"));
            imNotifyPort = Integer.parseInt(prop.getProperty("imNotifyPort"));
            imAdminPort = Integer.parseInt(prop.getProperty("imAdminPort"));
            ospnServicePort = Integer.parseInt(prop.getProperty("ospnServicePort"));
            imWebsockPort = Integer.parseInt(prop.getProperty("imWebsockPort"));
            imHttpPort = Integer.parseInt(prop.getProperty("imHttpPort"));

            String cmds = prop.getProperty("cmdForward");
            if(cmds != null){
                String[] cs = cmds.split(" +");
                cmdForward.addAll(Arrays.asList(cs));
            }

            msgDelete = prop.getProperty("msgDelete", "false").equalsIgnoreCase("true");
            standAlone = prop.getProperty("standAlone", "false").equalsIgnoreCase("true");
            needRelated = prop.getProperty("needRelated", "true").equalsIgnoreCase("true");
            autoFriendInternal = prop.getProperty("autoFriendInternal", "false").equalsIgnoreCase("true");
            autoFriendExternal = prop.getProperty("autoFriendExternal", "false").equalsIgnoreCase("true");
            appRegisterUser = prop.getProperty("appRegisterUser", "true").equalsIgnoreCase("true");

            urlSpace = prop.getProperty("urlSpace", "");
            logInfo("urlSpace: "+urlSpace);

            service = db.getServiceID();
            if (service == null) {
                service = new CryptData();
                String[] osnID = ECUtils.createOsnID("service");
                if(osnID == null)
                    throw new Exception("create serviceID error");
                service.osnID = osnID[0];
                service.osnKey = osnID[1];
                db.setServiceID(service);
            }
        }
        catch (Exception e){
            logError(e);
        }
    }
    public static void initExtention(){
        CommandData command = getCommand("Message");
        boolean isMsgVerify = prop.getProperty("msgVerify", "true").equalsIgnoreCase("true");
        command.setNeedVerify(isMsgVerify);
        logInfo("message verify: "+isMsgVerify);
    }

    public static void setCommand(String version, String command, long flag, Function<SessionData,Void> run){
        cmdMap.put(command, new CommandData(version, command, flag, run));
    }
    public static CommandData getCommand(String command){
        return cmdMap.get(command);
    }
    public static SessionData getSessionData(ChannelHandlerContext ctx){
        return sessionMap.get(ctx);
    }
    public static SessionData getSessionData(ChannelHandlerContext ctx, boolean remote, boolean webSock, JSONObject json){
        SessionData sessionData = getSessionData(ctx);
        if(sessionData == null)
            sessionData = new SessionData(ctx);
        sessionData.setData(remote,webSock,json);
        return sessionData;
    }
    public static void delSessionData(SessionData sessionData){
        sessionMap.remove(sessionData.ctx);
        synchronized (userLock){
            if(sessionData.user != null && sessionData.user.session == sessionData)
                sessionData.user.session = null;
        }
        sessionData.user = null;
        sessionData.fromUser = null;
        sessionData.toUser = null;
        sessionData.toGroup = null;
        sessionData.ctx.close();
    }
    public static UserData getUserDataByName(String userName){
        UserData userData = db.readUserByName(userName);
        if(userData != null){
            userMap.put(userData.osnID, userData);
            readUserInfo(userData);
        }
        return userData;
    }
    public static UserData getUserData(String userID){
        UserData userData = userMap.get(userID);
        if(userData == null) {
            userData = db.readUserByID(userID);
            if(userData != null) {
                userMap.put(userID, userData);
                readUserInfo(userData);
            }
        }
        return userData;
    }
    public static GroupData getGroupData(String groupID){
        GroupData groupData = groupMap.get(groupID);
        if(groupData == null) {
            groupData = db.readGroup(groupID);
            if(groupData != null) {
                List<MemberData> members = db.listMember(groupID);
                for(MemberData m : members) {
                    groupData.addMember(m.osnID);
                    if(m.mute != 0)
                        groupData.addMute(m.osnID);
                }
                groupMap.put(groupID, groupData);
            }
        }
        return groupData;
    }
    public static MemberData getMemberData(String groupID, String memberID){
        return db.readMember(groupID, memberID);
    }
    public static LitappData getLitappData(String serviceID){
        LitappData litappData = litappMap.get(serviceID);
        if(litappData == null){
            litappData = db.readLitapp(serviceID);
            if(litappData != null)
                litappMap.put(serviceID, litappData);
        }
        return litappData;
    }
    public static CryptData getCryptData(String osnID){
        if(isUser(osnID))
            return getUserData(osnID);
        else if(isGroup(osnID))
            return getGroupData(osnID);
        else if(isService(osnID))
            return service;
        return null;
    }
    public static boolean isService(String osnID){
        return osnID.startsWith("OSNS");
    }
    public static boolean isGroup(String osnID){
        return osnID.startsWith("OSNG");
    }
    public static boolean isUser(String osnID){
        return osnID.startsWith("OSNU");
    }
    public static boolean isOsnID(String osnID){
        return osnID.startsWith("OSN");
    }
    public static void resetHelp(){
        Date date = new Date();
        SimpleDateFormat dateFormat = new SimpleDateFormat("dd");
        if(currentDay == null){
            currentDay = dateFormat.format(date);
            return;
        }
        String day = dateFormat.format(date);
        if(!currentDay.equalsIgnoreCase(day)){
            helpOut = 0;
            helpIn = 0;
        }
    }

    private static void readUserInfo(UserData userData){
        try {
            List<FriendData> friends = db.listFriend(userData.osnID);
            for(FriendData f:friends) {
                userData.addFriend(f.friendID);
                if(f.state == FriendStatus_Blacked)
                    userData.addBlack(f.friendID);
            }
            List<String> members = db.listGroup(userData.osnID, true);
            for(String m:members)
                userData.addGroup(m);
        }
        catch (Exception e){
            logError(e);
        }
    }
}
