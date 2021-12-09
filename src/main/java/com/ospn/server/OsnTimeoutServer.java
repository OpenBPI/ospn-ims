package com.ospn.server;

import com.ospn.common.OsnUtils;
import com.ospn.OsnIMServer;
import com.ospn.core.IMData;
import com.ospn.data.CryptData;
import com.ospn.data.SessionData;
import com.ospn.data.UserData;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import static com.ospn.common.OsnUtils.logError;
import static com.ospn.common.OsnUtils.logInfo;
import static com.ospn.core.IMData.*;

public class OsnTimeoutServer {
    public static void worker(){
        List<SessionData> sessionList = new ArrayList<>();
        while(true){
            try{
                sessionList.clear();
                Enumeration<SessionData> enumeration = IMData.sessionMap.elements();
                long timeBase = System.currentTimeMillis();
                while(enumeration.hasMoreElements()){
                    SessionData sessionData = enumeration.nextElement();
                    if(timeBase > sessionData.timeHeart && (timeBase - sessionData.timeHeart > 30000))
                        sessionList.add(sessionData);
                }

                for(SessionData sessionData : sessionList){
                    UserData userData = sessionData.user;
                    if(userData != null)
                        logInfo("userID: " + userData.osnID + ", name: " + userData.name);
                    delSessionData(sessionData);
                }

                Thread.sleep(10000);
            }
            catch (Exception e){
                logError(e);
            }
        }
    }
    public static void mysql(){
        try {
            while(true) {
                Thread.sleep(60 * 60 * 1000);
                CryptData cryptData = db.getServiceID();
                if (cryptData == null)
                    logError("db connection lost");
            }
        }
        catch (Exception ignored){
        }
    }
    public static void initServer(){
        new Thread(OsnTimeoutServer::worker).start();
        new Thread(OsnTimeoutServer::mysql).start();
    }
}
