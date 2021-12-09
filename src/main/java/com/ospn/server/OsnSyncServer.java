package com.ospn.server;

import com.ospn.OsnIMServer;
import com.ospn.data.GroupData;
import com.ospn.data.LitappData;
import com.ospn.data.UserData;

import java.io.*;
import java.util.List;
import java.util.Properties;

import static com.ospn.common.OsnUtils.logError;
import static com.ospn.common.OsnUtils.logInfo;
import static com.ospn.core.IMData.*;

public class OsnSyncServer {

    private static void worker(){
        String osnID = null;
        while(true){
            List<UserData> userList = db.listUser(osnID, 100);
            if(userList.isEmpty())
                break;
            for(UserData userData : userList)
                OsnIMServer.Inst.pushOsnID(userData);
            osnID = userList.get(userList.size()-1).osnID;
        }
        osnID = null;
        while(true){
            List<GroupData> groupList = db.listGroup(osnID, 100);
            if(groupList.isEmpty())
                break;
            for(GroupData groupData : groupList)
                OsnIMServer.Inst.pushOsnID(groupData);
            osnID = groupList.get(groupList.size()-1).osnID;
        }
        List<LitappData> litappList = db.listLitapp();
        for(LitappData litappData : litappList)
            OsnIMServer.Inst.pushOsnID(litappData);
    }
    public static void initServer(){
        try{
            String configFile = "config.properties";
            File file = new File(configFile);
            if(!file.exists())
                logInfo("create config file: "+file.createNewFile());

            Properties prop = new Properties();
            prop.load(new FileInputStream(configFile));
            String initSync = prop.getProperty("initSync", null);
            if(initSync == null || !initSync.equalsIgnoreCase("ok")){
                prop.setProperty("initSync", "ok");
                prop.store(new FileOutputStream(configFile), "");

                logInfo("start initSync");

                new Thread(OsnSyncServer::worker).start();
            }
        }
        catch (Exception e){
            logError(e);
        }
    }
}
