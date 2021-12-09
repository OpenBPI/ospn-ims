package com.ospn.data;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;

public class TransferData {
    public String key;
    public BufferedOutputStream writer;
    public BufferedInputStream reader;
    public long timestamp;
}
