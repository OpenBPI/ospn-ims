package com.ospn.server;

import com.alibaba.fastjson.JSONObject;
import com.ospn.OsnIMServer;
import com.ospn.data.SessionData;
import com.ospn.data.UserData;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;

import static com.ospn.common.OsnUtils.logError;
import static com.ospn.common.OsnUtils.logInfo;
import static com.ospn.core.IMData.delSessionData;
import static com.ospn.core.IMData.getSessionData;

public class OsnIMSServer extends SimpleChannelInboundHandler<JSONObject> {

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, JSONObject json) {
        SessionData sessionData = getSessionData(ctx,false,false,json);
        OsnIMServer.Inst.handleMessage(sessionData);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        SessionData sessionData = getSessionData(ctx);
        if(sessionData != null) {
            UserData userData = sessionData.user;
            logInfo("user: " + (userData == null ? "null" : userData.name));
            delSessionData(sessionData);
        }
        ctx.close();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        super.exceptionCaught(ctx, cause);
        ctx.close();
    }
}
