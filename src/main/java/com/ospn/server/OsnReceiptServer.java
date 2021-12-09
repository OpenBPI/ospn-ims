package com.ospn.server;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.ospn.Constant;
import com.ospn.OsnIMServer;
import com.ospn.core.IMData;
import com.ospn.data.CryptData;
import com.ospn.data.MessageData;

import java.util.List;

import static com.ospn.common.OsnUtils.logError;
import static com.ospn.core.IMData.db;
import static com.ospn.utils.CryptUtils.wrapMessage;

public class OsnReceiptServer {
    public static void worker(){
        db.clearReceipts();
        while(true){
            try{
                long timeBase = System.currentTimeMillis();
                List<MessageData> msgList = db.queryReceipts();
                for(MessageData m:msgList){
                    if(timeBase < m.timeStamp)
                        continue;
                    long diff = timeBase - m.timeStamp;
                    if(diff > 60*5*1000)
                        db.updateReceipt(m.hash, Constant.ReceiptStatus_Error);
                    else if(diff > 30 * 1000){
                        CryptData cryptData = IMData.getCryptData(m.fromID);
                        if(cryptData == null)
                            db.updateReceipt(m.hash, Constant.ReceiptStatus_Error);
                        else {
                            try {
                                JSONObject data = JSON.parseObject(m.data);
                                JSONObject json = wrapMessage("waitReceipt", m.fromID, m.toID, data, cryptData.osnKey, null);
                                OsnIMServer.Inst.sendOsxJson(json);
                            }
                            catch (Exception e){
                                logError(e);
                                db.updateReceipt(m.hash, Constant.ReceiptStatus_Error);
                            }
                        }
                    }
                }
            }
            catch (Exception e){
                logError(e);
            }
            try{Thread.sleep(1000*30);}catch (Exception e){logError(e);}
        }
    }
    public static void initServer(){
        new Thread(OsnReceiptServer::worker).start();
    }
}
