package com.ospn.data;

import java.util.function.Function;

public class CommandData {
    public String version;
    public String command;
    public long flag;
    public boolean needVerify;
    public boolean needReceipt;
    public boolean needOnline;
    public boolean needRelated;
    public boolean needSave;
    public boolean needSaveOut;
    public boolean needContent;
    public boolean needBlock;
    public Function<SessionData,Void> run;

    public static long NeedVerify = 1;     //需要校验
    public static long NeedReceipt = 2;    //需要回执
    public static long NeedOnline = 4;     //需要在线
    public static long NeedRelated = 8;    //需要关联
    public static long NeedSave = 0x10;    //需要保存（双向）
    public static long NeedContent = 0x20; //群组相关的不能使用，就算转发后，有可能需要进一步处理
    public static long NeedBlock = 0x40;   //无关联丢弃
    public static long NeedSaveOut = 0x80; //发给客户端的消息

    public CommandData(String version, String command, long flag, Function<SessionData,Void> run){
        this.version = version;
        this.command = command;
        this.flag = flag;
        this.run = run;
        this.needVerify = (flag&NeedVerify) != 0;
        this.needReceipt = (flag&NeedReceipt) != 0;
        this.needOnline = (flag&NeedOnline) != 0;
        this.needRelated = (flag&NeedRelated) != 0;
        this.needSave = (flag&NeedSave) != 0;
        this.needContent = (flag&NeedContent) != 0;
        this.needBlock = (flag&NeedBlock) != 0;
        this.needSaveOut = (flag&NeedSaveOut) != 0;
    }

    public void setNeedVerify(boolean verify) {
        this.needVerify = verify;
        if(verify){
            this.flag |= NeedVerify;
        } else {
            this.flag &= ~NeedVerify;
        }
    }
}
