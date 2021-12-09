package com.ospn;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.ospn.common.ECUtils;
import com.ospn.common.OsnSender;
import com.ospn.common.OsnServer;
import com.ospn.common.OsnUtils;
import com.ospn.core.IMData;
import com.ospn.data.*;
import com.ospn.server.*;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpRequestDecoder;
import io.netty.handler.codec.http.HttpResponseEncoder;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.stream.ChunkedWriteHandler;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static com.ospn.Constant.*;
import static com.ospn.common.OsnUtils.*;
import static com.ospn.core.IMData.*;
import static com.ospn.data.CommandData.*;
import static com.ospn.data.FriendData.*;
import static com.ospn.data.GroupData.*;
import static com.ospn.data.MemberData.*;
import static com.ospn.data.MessageData.toMessageData;
import static com.ospn.utils.CryptUtils.*;

public class OsnIMServer extends OsnServer {
    public static void main(String[] args) {
        try {
            OsnUtils.init("ims");
            OsnIMServer.Inst = new OsnIMServer();
            OsnIMServer.Inst.StartServer();
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
    }

    public static OsnSender osxSender = null;
    public static OsnIMServer Inst = null;

    public static class JsonSender implements OsnSender.Callback {
        public void onDisconnect(OsnSender sender, String error) {
            try {
                logInfo(sender.mIp + ":" + sender.mPort + "/" + sender.mTarget + ", error: " + error);
                Thread.sleep(2000);
                osxSender = OsnSender.newInstance(sender);
            } catch (Exception ignore) {
            }
        }

        public void onCacheJson(OsnSender sender, JSONObject json) {
            logInfo("drop target: " + sender.mTarget + ", ip: " + sender.mIp);
        }

        public List<JSONObject> onReadCache(OsnSender sender, String target, int count) {
            return new ArrayList<>();
        }
    }

    private void StartServer() {
        try {
            IMData.init();
            setCommand("1", "Heart", 0, Inst::Heart);
            setCommand("1", "Login", 0, Inst::Login);
            setCommand("1", "Register", 0, Inst::Register);
            setCommand("1", "AddFriend", NeedVerify | NeedReceipt | NeedOnline | NeedSaveOut, Inst::AddFriend);
            setCommand("1", "DelFriend", NeedVerify | NeedOnline | NeedContent, Inst::DelFriend);
            setCommand("1", "AgreeFriend", NeedVerify | NeedReceipt | NeedOnline | NeedContent, Inst::AgreeFriend);
            setCommand("1", "RejectFriend", NeedVerify | NeedReceipt | NeedOnline | NeedContent, Inst::RejectFriend);
            setCommand("1", "Message", NeedVerify | NeedReceipt | NeedRelated | NeedSave | NeedBlock, Inst::Message);
            setCommand("1", "SetMessage", NeedVerify | NeedOnline | NeedSaveOut, Inst::SetMessage);
            setCommand("1", "Complete", NeedVerify, Inst::Complete);
            setCommand("1", "MessageSync", NeedVerify | NeedOnline | NeedContent, Inst::MessageSync);
            setCommand("1", "MessageLoad", NeedVerify | NeedOnline | NeedContent, Inst::MessageLoad);
            setCommand("1", "GetUserInfo", NeedVerify | NeedOnline, Inst::GetUserInfo);
            setCommand("1", "SetUserInfo", NeedVerify | NeedOnline | NeedContent, Inst::SetUserInfo);
            setCommand("1", "GetFriendInfo", NeedVerify | NeedOnline | NeedContent, Inst::GetFriendInfo);
            setCommand("1", "SetFriendInfo", NeedVerify | NeedOnline | NeedContent, Inst::SetFriendInfo);
            setCommand("1", "GetConversationList", NeedVerify | NeedOnline, Inst::GetConversationList);
            setCommand("1", "GetConversationInfo", NeedVerify | NeedOnline | NeedContent, Inst::GetConversationInfo);
            setCommand("1", "SetConversationInfo", NeedVerify | NeedOnline | NeedContent, Inst::SetConversationInfo);
            setCommand("1", "UserInfo", 0, Inst::Forwarder);
            setCommand("1", "GroupInfo", 0, Inst::Forwarder);
            setCommand("1", "MemberInfo", 0, Inst::Forwarder);
            setCommand("1", "ServiceInfo", 0, Inst::Forwarder);
            setCommand("1", "UserUpdate", NeedVerify | NeedReceipt | NeedSave | NeedRelated, Inst::Forwarder);
            setCommand("1", "GroupUpdate", NeedVerify | NeedReceipt | NeedSave | NeedRelated, Inst::GroupUpdate);
            setCommand("1", "InviteGroup", NeedVerify | NeedReceipt | NeedSaveOut, Inst::InviteGroup);
            setCommand("1", "GetFriendList", NeedVerify | NeedOnline, Inst::GetFriendList);
            setCommand("1", "GetGroupList", NeedVerify | NeedOnline, Inst::GetGroupList);
            setCommand("1", "GetRequestList", NeedVerify | NeedOnline | NeedContent, Inst::GetRequestList);
            setCommand("1", "CreateGroup", NeedVerify | NeedOnline, Inst::CreateGroup);
            setCommand("1", "GetGroupInfo", NeedVerify | NeedOnline, Inst::GetGroupInfo);
            setCommand("1", "SetGroupInfo", NeedVerify | NeedOnline, Inst::SetGroupInfo);
            setCommand("1", "GetMemberInfo", NeedVerify | NeedOnline | NeedRelated, Inst::GetMemberInfo);
            setCommand("1", "SetMemberInfo", NeedVerify | NeedOnline, Inst::SetMemberInfo);
            setCommand("1", "AddMember", NeedVerify | NeedReceipt | NeedOnline, Inst::AddMember);
            setCommand("1", "DelMember", NeedVerify | NeedReceipt | NeedOnline, Inst::DelMember);
            setCommand("1", "QuitGroup", NeedVerify | NeedReceipt | NeedOnline, Inst::QuitGroup);
            setCommand("1", "DelGroup", NeedVerify | NeedReceipt | NeedOnline, Inst::DelGroup);
            setCommand("1", "JoinGroup", NeedVerify | NeedReceipt | NeedOnline | NeedSaveOut, Inst::JoinGroup);
            setCommand("1", "RejectGroup", NeedVerify | NeedReceipt | NeedOnline, Inst::RejectGroup);
            setCommand("1", "AgreeMember", NeedVerify | NeedReceipt | NeedOnline, Inst::AgreeMember);
            setCommand("1", "RejectMember", NeedVerify | NeedReceipt | NeedOnline, Inst::RejectMember);
            setCommand("1", "GetServiceInfo", NeedVerify, Inst::GetServiceInfo);

            setCommand("1", "waitReceipt", 0, Inst::WaitReceipt);
            setCommand("1", "findOsnID", 0, Inst::FindOsnID);

            setCommand("1", "Broadcast", 0, Inst::Broadcast);

            //IMData.initExtention();

            AddService(imServicePort, new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel arg0) {
                    arg0.pipeline().addLast(new MessageDecoder());
                    arg0.pipeline().addLast(new MessageEncoder());
                    arg0.pipeline().addLast(new OsnIMSServer());
                }
            });
            AddService(imNotifyPort, new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel arg0) {
                    arg0.pipeline().addLast(new MessageDecoder());
                    arg0.pipeline().addLast(new MessageEncoder());
                    arg0.pipeline().addLast(new OsnOSXServer());
                }
            });
            AddService(imAdminPort, new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel arg0) {
                    arg0.pipeline().addLast("http-decoder", new HttpRequestDecoder());
                    arg0.pipeline().addLast("aggregator", new HttpObjectAggregator(65536));
                    arg0.pipeline().addLast("http-encoder", new HttpResponseEncoder());
                    arg0.pipeline().addLast("http-chunked", new ChunkedWriteHandler());
                    arg0.pipeline().addLast("handler", new OsnAdminServer());
                }
            });
            AddService(imWebsockPort, new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel arg0) {
                    arg0.pipeline().addLast("http-codec", new HttpServerCodec());
                    arg0.pipeline().addLast("aggregator", new HttpObjectAggregator(65536));
                    arg0.pipeline().addLast("http-chunked", new ChunkedWriteHandler());
                    arg0.pipeline().addLast("handler", new OsnWSServer());
                }
            });
            AddService(imHttpPort, new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel arg0) {
                    arg0.pipeline().addLast("http-codec", new HttpServerCodec());
                    arg0.pipeline().addLast("http-chunked", new ChunkedWriteHandler());
                    arg0.pipeline().addLast("handler", new OsnFileServer());
                }
            });

            File file = new File("cache");
            if (!file.exists()) {
                if (!file.mkdir())
                    logInfo("mkdir cache failed");
            }
            file = new File("portrait");
            if (!file.exists()) {
                if (!file.mkdir())
                    logInfo("mkdir portrait failed");
            }
            osxSender = OsnSender.newInstance(ipConnector, ospnServicePort, null, false, 2000, new JsonSender(), null);

            OsnTimeoutServer.initServer();
            OsnReceiptServer.initServer();
            OsnSyncServer.initServer();
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
    }

    public void pushOsnID(CryptData cryptData) {
        JSONObject json = new JSONObject();
        json.put("command", "pushOsnID");
        json.put("osnID", cryptData.osnID);
        json.put("osnKey", cryptData.osnKey);
        OsnIMServer.Inst.sendOsxJson(json);
        logInfo("osnID: " + cryptData.osnID);
    }

    public void sendOsxJson(JSONObject json) {
        if (IMData.standAlone)
            return;
        CommandData cmd = getCommand(json.getString("command"));
        if (cmd != null && cmd.needReceipt)
            db.insertReceipt(toMessageData(json, ReceiptStatus_Wait));
        //sendJson(ipConnector, ospnServicePort, json);
        osxSender.send(json);
    }

    private void saveClientJson(JSONObject json) {
        CommandData cmd = getCommand(json.getString("command"));
        if (cmd != null && (cmd.needSave || cmd.needSaveOut)) {
            if (!json.containsKey("saved")) {
                json.put("saved", true);
                db.insertMessage(toMessageData(json, MessageStatus_Saved));
            }
        }
    }

    private void sendClientJson(SessionData sessionData, JSONObject json) {
        saveClientJson(json);
        json.remove("saved");
        if (sessionData.webSock) {
            if (json.containsKey("ecckey") && sessionData.user != null)
                toAesMessage(json, sessionData.user.osnKey);
            OsnWSServer.sendClientJson(sessionData, json);
        } else {
            sessionData.ctx.writeAndFlush(json);
        }
    }

    private void sendClientJson(UserData userData, JSONObject json) {
        saveClientJson(json);
        if (userData.session == null)
            logInfo("user no login: " + userData.osnID);
        else
            sendClientJson(userData.session, json);
    }

    private void sendUserJson(String userID, JSONObject json) {
        UserData userData = getUserData(userID);
        if (userData == null)
            sendOsxJson(json);
        else
            sendClientJson(userData, json);
    }

    private Void sendReplyCode(SessionData sessionData, ErrorData error, JSONObject json) {
        if (sessionData == null)
            return null;
        if (error != null)
            OsnUtils.logInfo3(error.toString());
        if (sessionData.remote)
            return null;
        JSONObject data = new JSONObject();
        data.put("command", "Reply");
        data.put("ver", "1");
        data.put("id", sessionData.json.getString("id"));
        data.put("errCode", error == null ? "0:success" : error.toString());
        data.put("crypto", "none");
        data.put("content", json == null ? "{}" : json.toString());
        data.put("timestamp", System.currentTimeMillis());
        sendClientJson(sessionData, data);
        return null;
    }

    private ErrorData forwardMessage(SessionData sessionData, JSONObject json) {
        ErrorData error = null;
        try {
            String to = json.getString("to");
            String from = json.getString("from");
            String command = json.getString("command");
            if (isGroup(to)) {
                GroupData groupData = getGroupData(to);
                if (groupData == null) {
                    if (!sessionData.remote) {
                        sendOsxJson(json);
                        return null;
                    }
                    logInfo("no find groupID: " + to);
                    return E_groupNoFind;
                }
                forwardGroup(groupData, json);
                return null;
            }
            UserData userData = getUserData(to);
            if (sessionData.remote) {
                if (userData == null) {
                    OsnUtils.logInfo("no my user: " + to);
                    error = E_userNoFind;
                } else {
                    sendClientJson(userData, json);
                    OsnUtils.logInfo("recv remote: " + command + ", from: " + from + " to: " + to);
                }
            } else {
                if (userData == null) {
                    sendOsxJson(json);
                    OsnUtils.logInfo("send remote: " + command + ", from: " + from + ", to: " + to);
                } else {
                    sendClientJson(userData, json);
                    OsnUtils.logInfo("recv local: " + command + ", from: " + from + ", to: " + to);
                }
            }
            return error;
        } catch (Exception e) {
            error = E_exception;
            OsnUtils.logError(e);
        }
        return error;
    }

    private void completeMessage(JSONObject json, boolean verify) {
        try {
            String command = json.getString("command");
            String osnID = json.getString("to");
            String userID = json.getString("from");
            if (verify) {
                json = takeMessage(json);
                if (json == null)
                    return;
                String hash = json.getString("hash");
                String sign = json.getString("sign");
                logInfo("verify: " + command + ", hash: " + hash);
                if (!ECUtils.osnVerify(userID, hash.getBytes(), sign))
                    OsnUtils.logInfo("verify failed hash: " + hash);
                else
                    db.updateReceipt(hash, Constant.ReceiptStatus_Complete);
            } else {
                String hash = json.getString("hash");
                CryptData cryptData = getCryptData(osnID);
                if (cryptData == null) {
                    logInfo("no find osnID: " + osnID);
                    return;
                }
                OsnUtils.logInfo("send: " + command + ", userID: " + userID + ", hash: " + hash);
                JSONObject data = new JSONObject();
                data.put("hash", hash);
                data.put("sign", ECUtils.osnSign(cryptData.osnKey, hash.getBytes()));
                json = wrapMessage("Complete", osnID, userID, data, cryptData.osnKey, null);
                sendOsxJson(json);
            }
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
    }

    private void toWebMessage(SessionData sessionData, MessageData messageData) {
        try {
            if (sessionData.webSock && messageData.toID.equalsIgnoreCase(sessionData.fromUser.osnID)) {
                JSONObject data = JSON.parseObject(messageData.data);
                String crypto = data.getString("crypto");
                if (crypto == null)
                    return;
                else if (crypto.equalsIgnoreCase("ecc-aes"))
                    toAesMessage(data, sessionData.user.osnKey);
                else if (crypto.equalsIgnoreCase("aes")) {
                    UserData userData = getUserData(messageData.fromID);
                    if (userData == null) {
                        logError("unknown src user: " + messageData.fromID);
                        return;
                    }
                    toLocalMessage(data, userData.osnKey, sessionData.user.osnKey);
                }
                messageData.data = data.toString();
            }
        } catch (Exception e) {
            logError(e);
        }
    }

    private GroupData getMyGroup(SessionData sessionData, JSONObject json) {
        if (sessionData.remote)
            return sessionData.toGroup;
        String groupID = json.getString("to");
        GroupData groupData = getGroupData(groupID);
        if (groupData == null) {
            sendOsxJson(json);
            logInfo("forward to groupID: " + groupID + ", command: " + json.getString("command"));
        }
        return groupData;
    }

    private void agreeFriend(String userID, String friendID) {
        FriendData friendData = db.readFriend(userID, friendID);
        if (friendData == null) {
            logInfo("no invited friend");
        } else {
            if (friendData.state == FriendStatus_Wait)
                newlyFriend(friendData.userID, friendData.friendID, friendData);
            else
                logInfo("already friend userID: " + friendData.userID + ", friendID: " + friendData.friendID + ", state: " + friendData.state);
        }
    }

    private void newlyGroup(GroupData groupData, String userID) {
        JSONObject data = groupData.toJson();
        data.put("state", "NewlyGroup");
        JSONObject json = makeMessage("GroupUpdate", groupData.osnID, userID, data, groupData.osnKey, null);
        OsnUtils.logInfo("userID: " + userID + ", groupID: " + groupData.osnID);
        sendUserJson(userID, json);
    }

    private void newlyMember(GroupData groupData, String userID) {
        MemberData memberData = getMemberData(groupData.osnID, userID);
        if (memberData == null) {
            memberData = new MemberData(userID, groupData.osnID, MemberType_Normal);
            if (!db.insertMember(memberData))
                logInfo("insertMember error");
        } else {
            memberData.type = MemberType_Normal;
            if (!db.updateMember(memberData, Collections.singletonList("type")))
                logInfo("updateMember error");
        }

        groupData.addMember(userID);
        newlyGroup(groupData, userID);

        UserData userData = getUserData(userID);
        if (userData != null)
            userData.addGroup(groupData.osnID);

        JSONObject data = new JSONObject();
        data.put("groupID", groupData.osnID);
        data.put("state", "AddMember");
        data.put("userList", Collections.singletonList(userID));
        notifyGroup(groupData, data);
    }

    private void newlyMemberRecord(String userID, String groupID) {
        if (db.isMember(userID, groupID)) {
            logInfo("already member record: " + userID + ", groupID: " + groupID);
            return;
        }
        UserData userData = getUserData(userID);
        if (userData == null) {
            logInfo("userID no found: " + userID);
            return;
        }
        userData.addGroup(groupID);
        MemberData memberData = new MemberData(userID, groupID, MemberType_Wait);
        if (!db.insertMember(memberData))
            OsnUtils.logInfo("insertMember error");
    }

    private void newlyFriend(String userID, String friendID, FriendData friendData) {
        if (friendData != null) {
            friendData.state = FriendStatus_Normal;
            if (!db.updateFriend(friendData, Collections.singletonList("state"))) {
                OsnUtils.logInfo("updateFriend error");
                return;
            }
        } else {
            if (!db.insertFriend(new FriendData(userID, friendID, FriendStatus_Normal))) {
                OsnUtils.logInfo("insertFriend error");
                return;
            }
        }
        logInfo("userID: " + userID + ", friendID: " + friendID);
        UserData userData = getUserData(userID);
        userData.addFriend(friendID);

        JSONObject data = new JSONObject();
        data.put("userID", userID);
        data.put("friendID", friendID);
        data.put("state", FriendStatus_Normal);
        JSONObject json = makeMessage("FriendUpdate", service.osnID, userID, data, service.osnKey, null);
        db.insertMessage(toMessageData(json, MessageStatus_Saved));
        sendUserJson(userID, json);
    }

    private void applyMember(GroupData groupData, String userID, String originalUser, JSONObject json) {
        OsnUtils.logInfo("userID: " + userID + ", originalUser: " + originalUser);
        JSONObject data = new JSONObject();
        data.put("originalUser", originalUser);
        data.put("userID", userID);
        JSONObject pack = packMessage(json, groupData.osnID, groupData.owner, data, groupData.osnKey);
        sendUserJson(groupData.owner, pack);
    }

    private void joinCheck(SessionData sessionData, String groupID, String userID, JSONObject json) {
        GroupData groupData = getGroupData(groupID);
        if (groupData == null) {
            logError("no my groupID: " + groupID);
            return;
        }

        MemberData memberData = getMemberData(groupID, userID);
        if (memberData == null) {
            //主动加群
            if (groupData.joinType == GroupJoinType_Free) {
                if (groupData.passType == GroupPassType_Free) {
                    sendReplyCode(sessionData, null, null);
                    newlyMember(groupData, userID);
                } else {
                    sendReplyCode(sessionData, null, null);
                    applyMember(groupData, userID, null, json);
                }
            } else {
                logInfo("no support join group");
                sendReplyCode(sessionData, E_noSupport, null);
            }
        } else {
            //邀请加群
            if (memberData.type != MemberType_Wait) {
                logInfo("already joined groupID: " + groupID);
                sendReplyCode(sessionData, null, null);
            } else {
                boolean newly = true;
                if (groupData.passType != GroupPassType_Free) {
                    if (!memberData.inviter.equalsIgnoreCase(groupData.owner)) {
                        newly = false;
                        sendReplyCode(sessionData, null, null);
                        applyMember(groupData, userID, memberData.inviter, json);
                    }
                }
                if (newly) {
                    sendReplyCode(sessionData, null, null);
                    newlyMember(groupData, userID);
                }
            }
        }
    }

    private void inviteCheck(boolean remote, UserData userData, String groupID, String originalUser, JSONObject json) {
        if (userData.isFriend(originalUser)) {
            logInfo("isFriend: " + userData.osnID + ", originalUser: " + originalUser);
            json = makeMessage("JoinGroup", userData.osnID, groupID, "{}", userData.osnKey, null);
            if (remote) {
                newlyMemberRecord(userData.osnID, groupID);
                sendOsxJson(json);
            } else
                joinCheck(null, groupID, userData.osnID, json);
        } else {
            logInfo("forward InviteGroup to client");
            sendClientJson(userData, json);
        }
    }

    private void inviteMember(String originalUser, String userID, GroupData groupData) {
        JSONObject data = new JSONObject();
        data.put("originalUser", originalUser);
        JSONObject json = makeMessage("InviteGroup", groupData.osnID, userID, data, groupData.osnKey, null);
        OsnUtils.logInfo("userID: " + userID + ", groupID: " + groupData.osnID);

        UserData userData = getUserData(userID);
        if (userData != null)
            inviteCheck(false, userData, groupData.osnID, originalUser, json);
        else
            sendOsxJson(json);
    }

    private void notifyGroup(GroupData groupData, JSONObject data) {
        try {
            for (String member : groupData.userList) {
                JSONObject json = makeMessage("GroupUpdate", groupData.osnID, member, data, groupData.osnKey, null);
                sendUserJson(member, json);
                OsnUtils.logInfo("state: " + data.getString("state") + ", memberID: " + member);
            }
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
    }

    private void forwardGroup(GroupData groupData, JSONObject json) {
        String userID = json.getString("from");
        OsnUtils.logInfo("forward group: [" + json.getString("command") + "] groupID: " + groupData.osnID + ", originalUser: " + json.getString("from"));
        for (String u : groupData.userList) {
            if (u.equalsIgnoreCase(userID))
                continue;
            JSONObject pack = packMessage(json, groupData.osnID, u, groupData.osnKey);
            sendUserJson(u, pack);
        }
    }

    private Void Heart(SessionData sessionData) {
        try {
            sessionData.timeHeart = System.currentTimeMillis();
            sendReplyCode(sessionData, null, null);
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void Register(SessionData sessionData) {
        try {
            if (!appRegisterUser) {
                sendReplyCode(sessionData, E_noSupport, null);
                return null;
            }
            JSONObject data = takeMessage(sessionData.json);
            if (data == null)
                return null;
            String username = data.getString("username");
            String password = data.getString("password");
            if (username == null || password == null) {
                sendReplyCode(sessionData, E_missData, null);
                return null;
            }
            if (db.isRegisterName(username)) {
                logInfo("user already exist: " + username);
                sendReplyCode(sessionData, E_userExist, null);
                return null;
            }
            UserData userData = OsnAdminServer.RegsiterUser(username, password);
            if (userData == null)
                sendReplyCode(sessionData, E_registFailed, null);
            else {
                data.clear();
                data.put("osnID", userData.osnID);
                sendReplyCode(sessionData, null, data);

                pushOsnID(userData);
            }
            OsnUtils.logInfo("userName: " + username + ", osnID: " + (userData == null ? "null" : userData.osnID));
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void Login(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            String userID = json.getString("user");
            boolean isNameLogin = json.getString("type").equalsIgnoreCase("user");
            UserData userData = isNameLogin ? getUserDataByName(userID) : getUserData(userID);
            if (userData == null) {
                logInfo("no register user: " + userID);
                sendReplyCode(sessionData, E_userNoFind, null);
                return null;
            }
            if (!json.containsKey("state")) {
                logInfo("need state");
                sendReplyCode(sessionData, E_missData, null);
                return null;
            }
            String state = json.getString("state");
            if (state.equalsIgnoreCase("request")) {
                sessionData.challenge = System.currentTimeMillis();
                sessionData.state = LoginState_Challenge;
                sessionData.deviceID = json.getString("deviceID");
                JSONObject data = new JSONObject();
                data.put("challenge", sessionData.challenge);
                String content = aesEncrypt(data.toString(), isNameLogin ? userData.password : userData.aesKey);
                data.clear();
                data.put("data", content);
                sendReplyCode(sessionData, null, data);
                logInfo("user: " + userID + ", state: " + state);
                sessionMap.put(sessionData.ctx, sessionData);
                return null;
            } else if (state.equalsIgnoreCase("verify")) {
                if (sessionData.state != LoginState_Challenge) {
                    sendReplyCode(sessionData, E_stateError, null);
                    return null;
                }
                String content = aesDecrypt(json.getString("data"), isNameLogin ? userData.password : userData.aesKey);
                JSONObject data = JSON.parseObject(content);
                if (!data.getString("user").equalsIgnoreCase(userID) ||
                        data.getLongValue("challenge") != sessionData.challenge) {
                    sendReplyCode(sessionData, E_verifyError, null);
                    return null;
                }
                sessionData.state = LoginState_Finish;

                JSONObject rData = new JSONObject();
                rData.put("aesKey", userData.aesKey);
                rData.put("msgKey", userData.msgKey);
                rData.put("osnID", userData.osnID);
                rData.put("osnKey", userData.osnKey);
                rData.put("serviceID", service.osnID);

                data.clear();
                data.put("data", aesEncrypt(rData.toString(), isNameLogin ? userData.password : userData.aesKey));

                userMap.put(userData.osnID, userData);
                if (userData.session != null) {
                    if (userData.session.deviceID != null && sessionData.deviceID != null &&
                            !sessionData.deviceID.equalsIgnoreCase(userData.session.deviceID)) {
                        data = makeMessage("KickOff", service.osnID, userID, "{}", userData.osnKey, null);
                        sendClientJson(userData.session, data);

                        logInfo("KickOff userID: " + userID + ", deviceID: " + userData.session.deviceID);
                    }
                    //sessionMap.remove(userData.session.ctx);
                    delSessionData(userData.session);
                }
                sessionMap.put(sessionData.ctx, sessionData);
                synchronized (userLock) {
                    userData.session = sessionData;
                }
                sessionData.user = userData;
                sessionData.timeHeart = System.currentTimeMillis();

                //sendClientJson(sessionData, result);
                sendReplyCode(sessionData, null, data);
                OsnUtils.logInfo("user: " + userData.osnID + ", name: " + userData.name);
            } else {
                sendReplyCode(sessionData, E_stateError, null);
            }
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void AddFriend(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            String userID = json.getString("from");
            String friendID = json.getString("to");

            OsnUtils.logInfo("userID: " + userID + ", friendID: " + friendID);

            if (sessionData.remote) {
                FriendData friendData = db.readFriend(friendID, userID);
                if (friendData != null) {
                    if (friendData.state == FriendStatus_Wait)
                        newlyFriend(friendID, userID, friendData);
                    json = makeMessage("AgreeFriend", friendID, userID, "{}", sessionData.toUser.osnKey, null);
                    sendOsxJson(json);
                } else if (autoFriendExternal) {
                    newlyFriend(friendID, userID, null);
                    json = makeMessage("AgreeFriend", friendID, userID, "{}", sessionData.toUser.osnKey, null);
                    sendOsxJson(json);
                    return null;
                }
            } else {
                FriendData friendData = db.readFriend(userID, friendID);
                if (friendData == null) {
                    friendData = new FriendData(userID, friendID, FriendStatus_Wait);
                    if (!db.insertFriend(friendData)) {
                        sendReplyCode(sessionData, E_dataBase, null);
                        return null;
                    }
                    sessionData.fromUser.addFriend(friendID);
                }
                if (autoFriendInternal) {
                    UserData userData = getUserData(friendID);
                    if (userData != null && !userData.isFriend(userID)) {
                        newlyFriend(friendID, userID, null);
                        newlyFriend(userID, friendID, friendData);
                        sendReplyCode(sessionData, null, null);
                        return null;
                    }
                }
            }
            ErrorData error = forwardMessage(sessionData, json);
            sendReplyCode(sessionData, error, null);
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void DelFriend(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            JSONObject data = sessionData.data;
            String userID = json.getString("from");
            String friendID = data.getString("friendID");

            OsnUtils.logInfo("userID: " + userID + ", friendID: " + friendID);

            if (!db.isFriend(userID, friendID)) {
                logInfo("no find friend: " + friendID);
                sendReplyCode(sessionData, E_friendNoFind, null);
                return null;
            }
            if (!db.deleteFriend(userID, friendID)) {
                sendReplyCode(sessionData, E_dataBase, null);
                return null;
            }
            sendReplyCode(sessionData, null, null);
            sessionData.fromUser.delFriend(friendID);

            data = new JSONObject();
            data.put("state", FriendStatus_Delete);
            data.put("userID", userID);
            data.put("friendID", friendID);
            json = makeMessage("FriendUpdate", service.osnID, userID, data, service.osnKey, null);
            sendClientJson(sessionData, json);
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void AgreeFriend(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            String userID = json.getString("from");
            String friendID = json.getString("to");

            OsnUtils.logInfo("userID: " + userID + ", friendID: " + friendID);

            FriendData friendData;
            if (sessionData.remote) {
                agreeFriend(friendID, userID);
            } else {
                friendData = db.readFriend(userID, friendID);
                if (friendData != null) {
                    if (friendData.state == FriendStatus_Wait)
                        newlyFriend(userID, friendID, friendData);
                    else
                        logInfo("already friend userID: " + userID + ", friendID: " + friendID);
                } else {
                    newlyFriend(userID, friendID, null);
                }
                sendReplyCode(sessionData, null, null);

                UserData userData = getUserData(friendID);
                if (userData != null)
                    agreeFriend(friendID, userID);
                else
                    forwardMessage(sessionData, json);
            }
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void RejectFriend(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            String userID = json.getString("from");
            String friendID = json.getString("to");

            FriendData friendData = db.readFriend(userID, friendID);
            if (friendData != null)
                db.deleteFriend(userID, friendID);
            sendReplyCode(sessionData, null, null);

            OsnUtils.logInfo("userID: " + userID + ", friendID: " + friendID);
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void Message(SessionData sessionData) {
        try {
            ErrorData error = forwardMessage(sessionData, sessionData.json);
            sendReplyCode(sessionData, error, null);
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }
    private Void SetMessage(SessionData sessionData) {
        try {
            if(!msgDelete){
                logInfo("no support userID: " + sessionData.fromUser.osnID);
                return sendReplyCode(sessionData, E_noSupport, null);
            }
            GroupData groupData = null;
            JSONObject json = sessionData.json;
            String target = json.getString("to");
            if(isGroup(target)){
                groupData = getMyGroup(sessionData, sessionData.json);
                if (groupData == null)
                    return null;
            }
            JSONObject data = takeMessage(json);
            assert data != null;
            String hash = data.getString("messageHash");
            logInfo("start delete "+(groupData==null?"user":"group")+" message: "+hash);
            MessageData messageData = db.queryMessage(hash);
            if(messageData == null){
                return sendReplyCode(sessionData, E_dataNoFind, null);
            }
            if(!messageData.fromID.equalsIgnoreCase(sessionData.fromUser.osnID)){
                return sendReplyCode(sessionData, E_noRight, null);
            }
            if(!db.deleteMessage(hash)){
                return sendReplyCode(sessionData, E_dataBase, null);
            }
            logInfo("delete message success: "+hash);
            if(sessionData.remote){
                sendClientJson(sessionData.toUser, json);
            } else {
                json = packMessage(json, sessionData.fromUser.osnID, target, sessionData.fromUser.osnKey);
                sendUserJson(target, json);
                sendReplyCode(sessionData, null, null);
            }
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }
    private Void MessageSync(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            JSONObject data = sessionData.data;
            String userID = json.getString("from");
            long timeStamp = data.getLong("timestamp");
            int count = data.containsKey("count") ? data.getInteger("count") : 20;
            if (count > 100) {
                sendReplyCode(sessionData, E_dataOverrun, null);
                return null;
            }

            List<MessageData> messageInfos = db.syncMessages(userID, timeStamp, count);
            JSONArray array = new JSONArray();
            for (MessageData messageData : messageInfos)
                array.add(messageData.data);

            data.clear();
            data.put("msgList", array);
            sendReplyCode(sessionData, null, data);

            OsnUtils.logInfo("userID: " + userID + ", timestamp: " + timeStamp + ", count: " + count + ", size: " + array.size());
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void MessageLoad(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            JSONObject data = sessionData.data;
            String userID = json.getString("from");
            String target = data.getString("userID");
            int count = data.getInteger("count");
            boolean before = data.getBoolean("before");
            long timeStamp = data.containsKey("timestamp") ? data.getLong("timestamp") : System.currentTimeMillis();
            if (count > 100) {
                sendReplyCode(sessionData, E_dataOverrun, null);
                return null;
            }

            List<MessageData> messageInfos = db.loadMessages(userID, target, timeStamp, before, count);
            JSONArray array = new JSONArray();
            for (MessageData messageData : messageInfos) {
                toWebMessage(sessionData, messageData);
                array.add(messageData.data);
            }
            data.clear();
            data.put("msgList", array);
            sendReplyCode(sessionData, null, data);

            OsnUtils.logInfo("userID: " + userID + ", target: " + target + ", timestamp: " + timeStamp + ", before: " + before + ", count: " + count + ", result: " + array.size());
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void GetUserInfo(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            String from = json.getString("from");
            String to = json.getString("to");

            OsnUtils.logInfo("from: " + from + ", to: " + to + ", remote: " + sessionData.remote);

            if (sessionData.remote) {
                JSONObject data = sessionData.toUser.toJson();
                JSONObject result = wrapMessage("UserInfo", to, from, data, sessionData.toUser.osnKey, json);
                sendOsxJson(result);
            } else {
                if (to == null || !to.startsWith("OSNU")) {
                    sendReplyCode(sessionData, E_userError, null);
                    return null;
                }
                UserData userData = getUserData(to);
                if (userData != null) {
                    JSONObject data = userData.toJson();
                    data = wrapMessage("UserInfo", to, from, data, userData.osnKey, json);
                    sendClientJson(sessionData, data);
                } else {
                    sendOsxJson(json);
                }
            }
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void SetUserInfo(SessionData sessionData) {
        try {
            JSONObject data = sessionData.data;

            OsnUtils.logInfo(data.toString());

            UserData userData = sessionData.fromUser;
            UserData userNotify = new UserData();
            userNotify.osnID = userData.osnID;

            List<String> keys = userData.parseKeys(data, userNotify);
            if(keys.isEmpty()){
                sendReplyCode(sessionData, E_missData, null);
                return null;
            }
            if (!db.updateUser(userNotify, keys)) {
                sendReplyCode(sessionData, E_dataBase, null);
                return null;
            }
            userData.updateKeys(keys, userNotify);
            sendReplyCode(sessionData, null, null);

            JSONArray array = new JSONArray();
            array.addAll(keys);
            data = userNotify.toJson();
            data.put("infoList", array);

            JSONObject json = makeMessage("UserUpdate", userData.osnID, userData.osnID, data, userData.osnKey, null);
            sendClientJson(sessionData, json);

            List<FriendData> friends = db.listFriend(userData.osnID);
            for (FriendData f : friends) {
                json = makeMessage("UserUpdate", userData.osnID, f.friendID, data, userData.osnKey, null);
                forwardMessage(sessionData, json);
            }
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void GetFriendList(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            List<FriendData> friendDataList = db.listFriend(sessionData.fromUser.osnID);
            JSONArray friendList = new JSONArray();
            for (FriendData f : friendDataList) {
                if (f.state != FriendStatus_Wait)
                    friendList.add(f.friendID);
            }
            JSONObject data = new JSONObject();
            data.put("friendList", friendList);
            JSONObject result = makeMessage("FriendList", service.osnID, sessionData.fromUser.osnID, data, service.osnKey, json);
            sendClientJson(sessionData, result);

            logInfo("userID: " + json.getString("from") + ", friendList: " + friendList.size());
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void GetFriendInfo(SessionData sessionData) {
        try {
            JSONObject data = sessionData.data;
            OsnUtils.logInfo(data.toString());

            String friendID = data.getString("friendID");
            FriendData friendData = db.readFriend(sessionData.user.osnID, friendID);
            if (friendData == null) {
                logInfo("no find friend: " + friendID);
                sendReplyCode(sessionData, E_friendNoFind, null);
                return null;
            }
            JSONObject result = makeMessage("FriendInfo", service.osnID, sessionData.fromUser.osnID, friendData.toJson(), service.osnKey, sessionData.json);
            sendClientJson(sessionData, result);
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void SetFriendInfo(SessionData sessionData) {
        try {
            JSONObject data = sessionData.data;
            OsnUtils.logInfo(data.toString());

            FriendData friendData = new FriendData();
            friendData.userID = sessionData.user.osnID;
            friendData.friendID = data.getString("friendID");

            List<String> keys = new ArrayList<>();
            if (data.containsKey("remarks")) {
                keys.add("remarks");
                friendData.remarks = data.getString("remarks");
            }
            if (data.containsKey("state")) {
                keys.add("state");
                friendData.state = data.getIntValue("state");
            }
            if (!db.updateFriend(friendData, keys)) {
                sendReplyCode(sessionData, E_dataBase, null);
                return null;
            }
            sendReplyCode(sessionData, null, null);

            if (friendData.state == FriendStatus_Blacked)
                sessionData.fromUser.addBlack(friendData.friendID);
            else if (friendData.state == FriendStatus_Normal)
                sessionData.fromUser.delBlack(friendData.friendID);
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void Complete(SessionData sessionData) {
        completeMessage(sessionData.json, true);
        return null;
    }

    private Void WaitReceipt(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            String hash = json.getString("hash");
            MessageData messageData = db.queryReceipt(hash);
            if (messageData == null) {
                json = takeMessage(json);
                sessionData.json = json;
                handleMessage(sessionData);
            } else {
                JSONObject data = takeMessage(json);
                if (data == null)
                    return null;
                completeMessage(data, false);
            }
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void Forwarder(SessionData sessionData) {
        forwardMessage(sessionData, sessionData.json);
        return null;
    }

    private Void GetConversationList(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            List<String> conversationList = db.listConversation(sessionData.user.osnID);
            JSONObject data = new JSONObject();
            data.put("conversationList", conversationList);
            JSONObject result = makeMessage("ConversationList", service.osnID, sessionData.fromUser.osnID, data, service.osnKey, json);
            sendClientJson(sessionData, result);

            logInfo("userID: " + json.getString("from") + ", conversationList: " + conversationList.size());
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void GetConversationInfo(SessionData sessionData) {
        try {
            JSONObject data = sessionData.data;
            String target = data.getString("target");
            String info = db.getConversationInfo(sessionData.user.osnID, target);
            if (info == null){
                sendReplyCode(sessionData, E_dataNoFind, null);
            } else {
                data = new JSONObject();
                data.put("info", info);
                sendReplyCode(sessionData, null, data);
            }
            logInfo("userID: " + sessionData.user.osnID + ", target: " + target
                    + ", info: " + (info != null ? info.length() : 0));
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void SetConversationInfo(SessionData sessionData) {
        try {
            JSONObject data = sessionData.data;
            String target = data.getString("target");
            String info = data.getString("info");
            if(target == null){
                return sendReplyCode(sessionData, E_missData, null);
            }
            ErrorData error = null;
            if(info == null){
                if(!db.delConversationInfo(sessionData.user.osnID, target)){
                    error = E_dataBase;
                }
            } else {
                if (!db.setConversationInfo(sessionData.user.osnID, target, info)){
                    error = E_dataBase;
                }
            }
            sendReplyCode(sessionData, error, null);

            logInfo("userID: " + sessionData.user.osnID + ", target: " + target + ", info: " + info);
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void GetRequestList(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            JSONObject data = sessionData.data;
            long timestamp = data.getLong("timestamp");
            int count = data.getIntValue("count");
            if (count > 20)
                count = 20;
            List<String> requests = new ArrayList<>();
            List<MessageData> requestList = db.loadRequest(sessionData.fromUser.osnID, timestamp, count);
            for (MessageData request : requestList) {
                toWebMessage(sessionData, request);
                json = new JSONObject();
                json.put("state", request.state);
                json.put("request", request.data);
                requests.add(json.toString());
            }
            data = new JSONObject();
            data.put("requestList", requests);
            sendReplyCode(sessionData, null, data);

            logInfo("userID: " + json.getString("from") + ", timestamp: " + timestamp + ", count: " + count + ", size: " + requestList.size());
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void CreateGroup(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            JSONObject data = takeMessage(json);
            if (data == null) {
                sendReplyCode(sessionData, E_cryptError, null);
                return null;
            }
            String owner = json.getString("from");
            String[] osnData = ECUtils.createOsnID("group");
            if (osnData == null)
                return null;
            GroupData groupData = new GroupData();
            groupData.osnID = osnData[0];
            groupData.name = data.getString("name");
            groupData.osnKey = osnData[1];
            groupData.owner = owner;
            groupData.portrait = data.getString("portrait");
            groupData.type = data.containsKey("type") ? data.getIntValue("type") : GroupType_Normal;
            groupData.joinType = data.containsKey("joinType") ? data.getIntValue("joinType") : GroupJoinType_Free;
            groupData.passType = data.containsKey("passType") ? data.getIntValue("passType") : GroupPassType_Free;
            groupData.validType();

            OsnUtils.logInfo("type: " + groupData.type + "[" + groupData.joinType + "], name: " + groupData.name + ", groupID: " + groupData.osnID + ", owner: " + groupData.owner);

            MemberData memberData;
            List<MemberData> members = new ArrayList<>();
            JSONArray userList = data.getJSONArray("userList");
            for (Object o : userList) {
                String u = (String) o;
                if (u.equalsIgnoreCase(owner)) {
                    memberData = new MemberData(u, groupData.osnID, MemberType_Owner);
                    groupData.addMember(owner);
                } else {
                    memberData = new MemberData(u, groupData.osnID, MemberType_Wait);
                }
                members.add(memberData);
                logInfo("member: " + u);
            }
            if (!groupData.hasMember(owner)) {
                memberData = new MemberData(owner, groupData.osnID, MemberType_Owner);
                members.add(memberData);
                groupData.addMember(owner);
                logInfo("add member: " + owner);
            }

            if (db.insertGroup(groupData) && db.insertMembers(members)) {
                for (Object m : userList) {
                    String u = (String) m;
                    if (u.equalsIgnoreCase(owner))
                        continue;
                    inviteMember(owner, u, groupData);
                }

                data.clear();
                data.put("groupID", groupData.osnID);
                JSONObject result = makeMessage("Replay", service.osnID, owner, data, service.osnKey, json);
                sendClientJson(sessionData, result);

                newlyGroup(groupData, owner);

                pushOsnID(groupData);
            } else
                sendReplyCode(sessionData, E_dataBase, null);
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void GetGroupInfo(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            String userID = json.getString("from");
            String groupID = json.getString("to");

            OsnUtils.logInfo("groupID: " + groupID + ", from: " + userID + ", remote: " + sessionData.remote);

            GroupData groupData = getMyGroup(sessionData, json);
            if (groupData == null)
                return null;
            JSONObject data = groupData.toJson();
            JSONObject result = wrapMessage("GroupInfo", groupID, userID, data, groupData.osnKey, json);
            if (sessionData.remote)
                sendOsxJson(result);
            else
                sendClientJson(sessionData, result);
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void SetGroupInfo(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            String userID = json.getString("from");
            String groupID = json.getString("to");

            OsnUtils.logInfo("userID: " + userID + ", groupID: " + groupID);

            GroupData groupData = getMyGroup(sessionData, json);
            if (groupData == null) {
                sendReplyCode(sessionData, null, null);
                return null;
            }
            if (!groupData.hasMember(userID)) {
                sendReplyCode(sessionData, E_noRight, null);
                return null;
            }
            JSONObject data = takeMessage(json);
            if (data == null) {
                sendReplyCode(sessionData, E_cryptError, null);
                return null;
            }
            if (data.containsKey("type") ||
                    data.containsKey("joinType") ||
                    data.containsKey("passType") ||
                    data.containsKey("mute")) {
                if (!userID.equalsIgnoreCase(groupData.owner)) {
                    sendReplyCode(sessionData, E_noRight, null);
                    return null;
                }
            }
            if (data.containsKey("name") || data.containsKey("portrait")) {
                if (!userID.equalsIgnoreCase(groupData.owner) && groupData.type == GroupType_Restrict) {
                    sendReplyCode(sessionData, E_noRight, null);
                    return null;
                }
            }

            OsnUtils.logInfo(data.toString());

            GroupData groupNotify = new GroupData();
            groupNotify.osnID = groupID;

            List<String> keys = new ArrayList<>();
            if (data.containsKey("name")) {
                groupNotify.name = data.getString("name");
                keys.add("name");
            }
            if (data.containsKey("portrait")) {
                groupNotify.portrait = data.getString("portrait");
                keys.add("portrait");
            }
            if (data.containsKey("type")) {
                groupNotify.type = data.getIntValue("type");
                keys.add("type");
            }
            if (data.containsKey("joinType")) {
                groupNotify.joinType = data.getIntValue("joinType");
                keys.add("joinType");
            }
            if (data.containsKey("passType")) {
                groupNotify.passType = data.getIntValue("passType");
                keys.add("passType");
            }
            if (data.containsKey("mute")) {
                groupNotify.mute = data.getIntValue("mute");
                keys.add("mute");
            }

            if (db.updateGroup(groupNotify, keys)) {
                groupData.update(groupNotify, keys);
                sendReplyCode(sessionData, null, null);

                JSONArray array = new JSONArray();
                array.addAll(keys);
                data = groupNotify.toJson();
                data.put("state", "UpdateGroup");
                data.put("infoList", array);
                notifyGroup(groupData, data);
            } else {
                sendReplyCode(sessionData, E_dataBase, null);
            }
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void JoinGroup(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            String userID = json.getString("from");
            String groupID = json.getString("to");

            OsnUtils.logInfo("userID: " + userID + ", groupID: " + groupID);

            GroupData groupData = getMyGroup(sessionData, json);
            if (groupData == null) {
                newlyMemberRecord(userID, groupID);
                sendReplyCode(sessionData, null, null);
                return null;
            }
            joinCheck(sessionData, groupID, userID, json);
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void RejectGroup(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            String userID = json.getString("from");
            String groupID = json.getString("to");

            OsnUtils.logInfo("userID: " + userID + ", groupID: " + groupID);

            GroupData groupData = getMyGroup(sessionData, json);
            if (groupData == null) {
                sendReplyCode(sessionData, null, null);
                return null;
            }
            MemberData memberData = getMemberData(groupID, userID);
            if (memberData == null) {
                logInfo("no find userID: " + userID);
                sendReplyCode(sessionData, E_userNoFind, null);
                return null;
            }
            db.deleteMember(userID, groupID);
            sendReplyCode(sessionData, null, null);
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void AgreeMember(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            String adminID = json.getString("from");
            String groupID = json.getString("to");

            OsnUtils.logInfo("adminID: " + adminID + ", groupID: " + groupID);

            GroupData groupData = getMyGroup(sessionData, json);
            if (groupData == null) {
                sendReplyCode(sessionData, null, null);
                return null;
            }
            JSONObject data = takeMessage(json);
            if (data == null) {
                sendReplyCode(sessionData, E_cryptError, null);
                return null;
            }
            String userID = data.getString("userID");
            MemberData memberData = getMemberData(groupID, adminID);
            if (memberData == null) {
                logInfo("no find adminID: " + adminID);
                sendReplyCode(sessionData, E_userNoFind, null);
                return null;
            }
            if (!memberData.isAdmin()) {
                logInfo("no right adminID: " + adminID);
                sendReplyCode(sessionData, E_noRight, null);
                return null;
            }
            sendReplyCode(sessionData, null, null);
            newlyMember(groupData, userID);
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void RejectMember(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            String adminID = json.getString("from");
            String groupID = json.getString("to");

            OsnUtils.logInfo("adminID: " + adminID + ", groupID: " + groupID);

            GroupData groupData = getMyGroup(sessionData, json);
            if (groupData == null) {
                sendReplyCode(sessionData, null, null);
                return null;
            }
            JSONObject data = takeMessage(json);
            if (data == null) {
                sendReplyCode(sessionData, E_cryptError, null);
                return null;
            }
            String userID = data.getString("userID");
            MemberData memberData = getMemberData(groupID, userID);
            if (memberData == null) {
                logInfo("no find adminID: " + adminID);
                sendReplyCode(sessionData, E_userNoFind, null);
                return null;
            }
            if (!db.deleteMember(userID, groupID))
                logInfo("deleteMember error");
            sendReplyCode(sessionData, null, null);
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void AddMember(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            String userID = json.getString("from");
            String groupID = json.getString("to");

            OsnUtils.logInfo("userID: " + userID + ", groupID: " + groupID);

            GroupData groupData = getMyGroup(sessionData, json);
            if (groupData == null) {
                sendReplyCode(sessionData, null, null);
                return null;
            }
            if (!groupData.hasMember(userID)) {
                sendReplyCode(sessionData, E_noRight, null);
                return null;
            }
            MemberData memberData = getMemberData(groupID, userID);
            if (memberData == null) {
                logError("getMemberData error, groupID: " + groupID + ", memberID: " + userID);
                sendReplyCode(sessionData, E_noRight, null);
                return null;
            }
            if (!groupData.checkJoinRight(memberData)) {
                sendReplyCode(sessionData, E_noRight, null);
                return null;
            }
            JSONObject data = takeMessage(json);
            if (data == null) {
                sendReplyCode(sessionData, E_cryptError, null);
                return null;
            }

            List<MemberData> addList = new ArrayList<>();
            List<MemberData> lackList = new ArrayList<>();
            JSONArray memberList = data.getJSONArray("memberList");
            for (Object o : memberList) {
                String m = (String) o;
                memberData = getMemberData(groupID, m);
                if (memberData != null) {
                    lackList.add(memberData);
                    logInfo("already in group userID: " + m + ", type: " + memberData.type);
                    continue;
                }
                addList.add(new MemberData(m, groupID, MemberType_Wait, userID));
            }
            if (addList.size() == 0) {
                sendReplyCode(sessionData, E_alreadyMember, null);
                if (lackList.size() != 0) {
                    for (MemberData m : lackList)
                        inviteMember(userID, m.osnID, groupData);
                }
                return null;
            }
            if (addList.size() + groupData.userList.size() > groupData.maxMember) {
                sendReplyCode(sessionData, E_maxLimits, null);
                return null;
            }
            if (!db.insertMembers(addList)) {
                sendReplyCode(sessionData, E_dataBase, null);
                return null;
            }
            //groupData.addMembers(addList);
            sendReplyCode(sessionData, null, null);
            for (MemberData m : addList)
                inviteMember(userID, m.osnID, groupData);
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void DelMember(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            String userID = json.getString("from");
            String groupID = json.getString("to");

            OsnUtils.logInfo("userID: " + userID + ", groupID: " + groupID);

            GroupData groupData = getMyGroup(sessionData, json);
            if (groupData == null) {
                sendReplyCode(sessionData, null, null);
                return null;
            }
            MemberData memberData = getMemberData(groupID, userID);
            if (memberData == null) {
                sendReplyCode(sessionData, E_memberNoFind, null);
                return null;
            }
            if (!memberData.isAdmin()) {
                sendReplyCode(sessionData, E_noRight, null);
                return null;
            }
            JSONObject data = takeMessage(json);
            if (data == null) {
                sendReplyCode(sessionData, E_cryptError, null);
                return null;
            }

            List<String> delList = new ArrayList<>();
            JSONArray memberList = data.getJSONArray("memberList");
            for (Object member : memberList) {
                String osnID = (String) member;
                if (groupData.hasMember(osnID))
                    delList.add(osnID);
            }
            if (delList.size() == 0) {
                sendReplyCode(sessionData, E_memberNoFind, null);
                return null;
            }
            if (!db.deleteMembers(groupID, delList)) {
                sendReplyCode(sessionData, E_userError, null);
                return null;
            }
            sendReplyCode(sessionData, null, null);

            data.clear();
            data.put("groupID", groupData.osnID);
            data.put("state", "DelMember");
            data.put("userList", delList);
            notifyGroup(groupData, data);

            groupData.delMembers(delList);
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void InviteGroup(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            JSONObject data = takeMessage(json);
            if (data == null) {
                sendReplyCode(sessionData, E_cryptError, null);
                return null;
            }
            String groupID = json.getString("from");
            String userID = json.getString("to");

            OsnUtils.logInfo("groupID: " + groupID + ", userID: " + userID);

            String originalUser = data.getString("originalUser");
            inviteCheck(true, sessionData.toUser, groupID, originalUser, json);
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void GetMemberInfo(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            String userID = json.getString("from");
            String groupID = json.getString("to");

            OsnUtils.logInfo("groupID: " + groupID + ", from: " + userID + ", remote: " + sessionData.remote);

            GroupData groupData = getMyGroup(sessionData, json);
            if (groupData == null)
                return null;

            if (!groupData.hasMember(userID)) {
                sendReplyCode(sessionData, E_noRight, null);
                return null;
            }

            List<MemberData> members = db.listMember(groupID);

            JSONObject data = new JSONObject();
            data.put("groupID", groupData);
            data.put("name", groupData.name);
            data.put("userList", members);
            JSONObject result = makeMessage("MemberInfo", groupID, userID, data, groupData.osnKey, json);
            if (sessionData.remote)
                sendOsxJson(result);
            else
                sendClientJson(sessionData, result);
            logInfo("size: " + members.size());
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void SetMemberInfo(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            String userID = json.getString("from");
            String groupID = json.getString("to");

            OsnUtils.logInfo("userID: " + userID + ", groupID: " + groupID);

            GroupData groupData = getMyGroup(sessionData, json);
            if (groupData == null) {
                sendReplyCode(sessionData, null, null);
                return null;
            }
            if (!groupData.hasMember(userID)) {
                sendReplyCode(sessionData, E_noRight, null);
                return null;
            }

            JSONObject data = takeMessage(json);
            if (data == null) {
                sendReplyCode(sessionData, E_cryptError, null);
                return null;
            }

            OsnUtils.logInfo(data.toString());

            MemberData memberInfo = new MemberData();
            memberInfo.groupID = groupID;
            memberInfo.osnID = userID;

            List<String> keys = new ArrayList<>();
            if (data.containsKey("nickName")) {
                memberInfo.nickName = data.getString("nickName");
                keys.add("nickName");
            }
            if (db.updateMember(memberInfo, keys)) {
                sendReplyCode(sessionData, null, null);

                data = new JSONObject();
                data.put("groupID", groupID);
                data.put("state", "UpdateMember");
                data.put("userList", Collections.singletonList(memberInfo));
                data.put("infoList", keys);
                notifyGroup(groupData, data);
            } else {
                sendReplyCode(sessionData, E_dataBase, null);
            }
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void QuitGroup(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            String userID = json.getString("from");
            String groupID = json.getString("to");

            OsnUtils.logInfo("userID: " + userID + ", groupID: " + groupID);

            GroupData groupData = getMyGroup(sessionData, json);
            if (groupData == null) {
                db.deleteMember(userID, groupID);
                sessionData.fromUser.delGroup(groupID);
                sendReplyCode(sessionData, null, null);
                return null;
            }

            if (!groupData.hasMember(userID)) {
                logInfo("no in group: " + userID);
                sendReplyCode(sessionData, E_memberNoFind, null);
                return null;
            }
            if (!db.deleteMember(userID, groupID)) {
                sendReplyCode(sessionData, E_dataBase, null);
                return null;
            }
            sendReplyCode(sessionData, null, null);

            JSONObject data = new JSONObject();
            data.put("groupID", groupData.osnID);
            data.put("state", "QuitGroup");
            data.put("userList", Collections.singletonList(userID));
            notifyGroup(groupData, data);

            groupData.delMember(userID);
            OsnUtils.logInfo(data.toString());
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void DelGroup(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            String userID = json.getString("from");
            String groupID = json.getString("to");

            OsnUtils.logInfo("userID: " + userID + ", groupID: " + groupID);

            GroupData groupData = getMyGroup(sessionData, json);
            if (groupData == null) {
                db.deleteMember(userID, groupID);
                sessionData.fromUser.delGroup(groupID);
                sendReplyCode(sessionData, null, null);
                return null;
            }

            if (!userID.equalsIgnoreCase(groupData.owner)) {
                logInfo("no owner");
                sendReplyCode(sessionData, E_noRight, null);
                return null;
            }
            JSONObject data;
            if (!db.deleteGroup(groupData) || !db.deleteMembers(groupID, new ArrayList<>(groupData.userList))) {
                sendReplyCode(sessionData, E_dataBase, null);
                return null;
            }
            sendReplyCode(sessionData, null, null);

            data = new JSONObject();
            data.put("groupID", groupData.osnID);
            data.put("state", "DelGroup");
            notifyGroup(groupData, data);

            groupMap.remove(groupID);
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void GetGroupList(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            String userID = json.getString("from");

            OsnUtils.logInfo("userID: " + userID);

            List<String> groupList = db.listGroup(sessionData.fromUser.osnID, false);
            JSONObject data = new JSONObject();
            data.put("groupList", groupList);
            OsnUtils.logInfo("groupList: " + groupList.size());

            JSONObject result = makeMessage("GroupList", service.osnID, sessionData.fromUser.osnID, data, service.osnKey, json);
            sendClientJson(sessionData, result);
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void GroupUpdate(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            JSONObject data = takeMessage(json);
            if (data == null) {
                sendReplyCode(sessionData, E_cryptError, null);
                return null;
            }
            String userID = json.getString("to");
            String groupID = json.getString("from");

            logInfo(data.toString());

            String state = data.getString("state");
            if (state.equalsIgnoreCase("DelGroup")) {
                if (sessionData.toUser.hasGroup(groupID)) {
                    db.deleteMember(userID, groupID);
                    sessionData.toUser.delGroup(groupID);
                }
            } else if (state.equalsIgnoreCase("DelMember") ||
                    state.equalsIgnoreCase("QuitGroup")) {
                JSONArray members = data.getJSONArray("userList");
                for (Object o : members) {
                    if (userID.equalsIgnoreCase((String) o)) {
                        db.deleteMember(userID, groupID);
                        sessionData.toUser.delGroup(groupID);
                        break;
                    }
                }
            } else if (state.equalsIgnoreCase("AddMember")) {
                JSONArray members = data.getJSONArray("userList");
                for (Object o : members) {
                    if (userID.equalsIgnoreCase((String) o)) {
                        MemberData memberData = getMemberData(groupID, userID);
                        if (memberData.type == MemberType_Wait) {
                            logInfo("update member type to Normal, memberID: " + userID + ", groupID: " + groupID);
                            memberData.type = MemberType_Normal;
                            db.updateMember(memberData, Collections.singletonList("type"));
                        }
                        break;
                    }
                }
            }
            Forwarder(sessionData);
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void GetServiceInfo(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            String userID = json.getString("from");
            String serviceID = json.getString("to");

            if (serviceID == null)
                return null;

            OsnUtils.logInfo("serviceID: " + serviceID + ", from: " + userID + ", remote: " + sessionData.remote);

            JSONObject result = null;
            if (serviceID.equalsIgnoreCase(service.osnID)) {
                JSONObject info = new JSONObject();
                info.put("type", "IMS");
                info.put("urlSpace", urlSpace);
                result = wrapMessage("ServiceInfo", serviceID, userID, info, service.osnKey, json);
            } else {
                LitappData litappData = getLitappData(serviceID);
                if (litappData != null) {
                    logInfo("litapp name: " + litappData.name);
                    result = wrapMessage("ServiceInfo", serviceID, userID, litappData.toJson(), litappData.osnKey, json);
                } else
                    logInfo("no my serviceID: " + serviceID);
            }

            if (result != null) {
                if (sessionData.remote)
                    sendOsxJson(result);
                else
                    sendClientJson(sessionData, result);
            } else {
                if (!sessionData.remote)
                    sendOsxJson(json);
            }
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
        return null;
    }

    private Void FindOsnID(SessionData sessionData) {
        JSONObject json = sessionData.json;
        JSONArray findedList = new JSONArray();
        JSONArray targetList = json.getJSONArray("targetList");
        String timeStamp = json.getString("timeStamp");
        if (timeStamp == null) {
            logError("miss timeStamp");
            return null;
        }
        //logInfo("recv targetList: "+targetList.toString());

        for (Object o : targetList) {
            String osnID = (String) o;
            CryptData cryptData = null;
            if (isUser(osnID)) {
                cryptData = getUserData(osnID);
            } else if (isGroup(osnID)) {
                cryptData = getGroupData(osnID);
            } else if (isService(osnID)) {
                if (osnID.equalsIgnoreCase(service.osnID))
                    cryptData = service;
                if (cryptData == null)
                    cryptData = getLitappData(osnID);
            }
            if (cryptData != null) {
                JSONObject data = new JSONObject();
                data.put("osnID", cryptData.osnID);
                data.put("sign", ECUtils.osnSign(cryptData.osnKey, timeStamp.getBytes(StandardCharsets.UTF_8)));
                findedList.add(data);
            }
        }
        if (!findedList.isEmpty()) {
            JSONObject data = new JSONObject();
            data.put("command", "haveOsnID");
            data.put("ip", json.getString("ip"));
            data.put("timeStamp", timeStamp);
            data.put("querySign", json.getString("querySign"));
            data.put("targetList", findedList);
            sendOsxJson(data);

            OsnUtils.logInfo("send findedList: " + findedList + ", ip: " + json.getString("ip"));
        }
        return null;
    }

    private Void Broadcast(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            JSONObject data = takeMessage(json);
            if (data == null)
                return null;
            String userID = json.getString("from");
            String content = data.getString("content");
            String decContent = new String(Base64.getDecoder().decode(content));
            logInfo("userID: " + userID + ", content: " + decContent);
            resetHelp();
            if (!sessionData.remote) {
                sendOsxJson(json);
                sendReplyCode(sessionData, null, null);
                ++helpOut;
            } else {
                ++helpIn;
            }
        } catch (Exception e){
            logError(e);
        }
        return null;
    }

    public ErrorData sendNotify(JSONObject json) {
        String to = json.getString("to");
        String from = json.getString("from");
        logInfo("from: " + from + ", to: " + to);
        sendUserJson(to, json);
        return null;
    }

    public void handleMessage(SessionData sessionData) {
        try {
            JSONObject json = sessionData.json;
            if (!sessionData.remote)
                sessionData.timeHeart = System.currentTimeMillis();
            String command = json.getString("command");
            CommandData commandData = getCommand(command);
            if (commandData == null) {
                logInfo("unknown command: " + command);
                return;
            }
            sessionData.command = commandData;
            if (commandData.needVerify) {
                long timestamp = Long.parseLong(json.getString("timestamp"));
                if (timestamp - System.currentTimeMillis() > 5 * 60 * 1000) {
                    sendReplyCode(sessionData, E_timeSync, null);
                    return;
                }
                String to = json.getString("to");
                String from = json.getString("from");
                if (sessionData.remote) {
                    if (isGroup(to)) {
                        sessionData.toGroup = getGroupData(to);
                        if (sessionData.toGroup == null) {
                            logInfo(commandData.command + ": no my groupID: " + to);
                            return;
                        }
                        if (needRelated && commandData.needRelated && !sessionData.toGroup.hasMember(from)) {
                            logInfo(commandData.command + ": need related");
                            return;
                        }
                    } else if (isUser(to)) {
                        sessionData.toUser = getUserData(to);
                        if (sessionData.toUser == null) {
                            logInfo(commandData.command + ": no my user: " + to);
                            return;
                        }
                        if (!isService(from)) {
                            if (needRelated && commandData.needRelated && !sessionData.toUser.isRelated(from)) {
                                logInfo(commandData.command + ": need related");
                                return;
                            }
                        }
                        if (commandData.needBlock && sessionData.toUser.isBlacked(from)) {
                            logInfo(commandData.command + ": is blacked");
                            return;
                        }
                    } else if (isService(to)) {
                        logInfo("serviceID: " + to);
                    } else {
                        logInfo(commandData.command + ": unknown dst osnID: " + to);
                        return;
                    }
                } else {
                    if (!isUser(from)) {
                        logInfo(commandData.command + ": unknown src osnID: " + from);
                        sendReplyCode(sessionData, E_userNoFind, null);
                        return;
                    }
                    sessionData.fromUser = getUserData(from);
                    if (sessionData.fromUser == null) {
                        logInfo(commandData.command + ": no my register userID: " + from);
                        sendReplyCode(sessionData, E_userNoFind, null);
                        return;
                    }
                    if (commandData.needOnline) {
                        if (sessionData.user == null) {
                            logInfo(commandData.command + ": need login");
                            sendReplyCode(sessionData, E_needLogin, null);
                            return;
                        }
                        if (sessionData.fromUser != sessionData.user) {
                            logInfo(commandData.command + ": no the login user: " + from);
                            sendReplyCode(sessionData, E_userError, null);
                            return;
                        }
                    }
                    if (needRelated && commandData.needRelated) {
                        if (isUser(to)) {
                            UserData userData = getUserData(to);
                            if (userData != null && !userData.isRelated(from)) {
                                logInfo(commandData.command + ": need related");
                                sendReplyCode(sessionData, E_friendNoFind, null);
                                return;
                            }
                        } else if (isGroup(to)) {
                            GroupData groupData = getGroupData(to);
                            if (groupData != null && !groupData.hasMember(from)) {
                                logInfo(commandData.command + ": need related");
                                sendReplyCode(sessionData, E_memberNoFind, null);
                                return;
                            }
                        }
                    }
                }
                ErrorData error = checkMessage(sessionData.json);
                if (error != null) {
                    sendReplyCode(sessionData, error, null);
                    return;
                }
                //2021.1.31 转换近端aes加密
                String crypto = json.getString("crypto");
                if (crypto != null && crypto.equalsIgnoreCase("aes")) {
                    if (sessionData.user == null) {
                        logInfo("no local user to convert aes: " + json.getString("from"));
                        sendReplyCode(sessionData, E_userNoFind, null);
                        return;
                    }
                    toEccMessage(json, sessionData.user.osnKey);
                }
                if (commandData.needReceipt && sessionData.remote)
                    completeMessage(json, false);
                if (commandData.needSave) {
                    db.insertMessage(toMessageData(json, MessageStatus_Saved));
                    json.put("saved", true);
                }
                if (commandData.needContent) {
                    sessionData.data = takeMessage(json);
                    if (sessionData.data == null) {
                        sendReplyCode(sessionData, E_cryptError, null);
                        return;
                    }
                }
            }
            commandData.run.apply(sessionData);
        } catch (Exception e) {
            OsnUtils.logError(e);
        }
    }
}
