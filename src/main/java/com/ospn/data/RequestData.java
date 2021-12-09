package com.ospn.data;

public class RequestData {
    public String userID;
    public String friendID;
    public String reason;
    public long timeStamp;

    public static int RequestStatus_Wait = 0;
    public static int RequestStatus_Agree = 2;
    public static int RequestStatus_Reject = 3;
}
