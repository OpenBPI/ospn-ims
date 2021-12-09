package com.ospn.data;

import com.alibaba.fastjson.JSONObject;
import io.netty.channel.ChannelHandlerContext;

public class SessionData {
    public ChannelHandlerContext ctx;
    public boolean remote;
    public boolean webSock;
    public JSONObject json;
    public UserData user;
    public long timeHeart;
    public long challenge;
    public int state;
    public String deviceID;

    public UserData fromUser = null;
    public UserData toUser = null;
    public GroupData toGroup = null;
    public JSONObject data = null;
    public CommandData command = null;

    public SessionData(ChannelHandlerContext ctx){
        this.ctx = ctx;
        user = null;
        timeHeart = System.currentTimeMillis();
    }
    public void setData(boolean remote, boolean webSock, JSONObject json){
        this.remote = remote;
        this.webSock = webSock;
        this.json = json;
    }
}
