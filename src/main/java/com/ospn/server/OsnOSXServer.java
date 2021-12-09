package com.ospn.server;

import com.alibaba.fastjson.JSONObject;
import com.ospn.OsnIMServer;
import com.ospn.data.SessionData;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;

import static com.ospn.common.OsnUtils.logError;
import static com.ospn.common.OsnUtils.logInfo;
import static com.ospn.core.IMData.getSessionData;

public class OsnOSXServer extends SimpleChannelInboundHandler<JSONObject> {

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, JSONObject json) throws Exception {
        String command = json.getString("command");
        if(command != null && command.equalsIgnoreCase("Heart"))
            ctx.writeAndFlush(json);
        else {
            SessionData sessionData = getSessionData(ctx, true, false, json);
            OsnIMServer.Inst.handleMessage(sessionData);
        }
    }
    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        ctx.close();
    }
    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        super.exceptionCaught(ctx, cause);
        ctx.close();
    }
}
