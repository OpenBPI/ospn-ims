import java.io.File;
import java.io.FileOutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;

public class LogFile {
    static FileOutputStream mLogger = null;

    static public void initLog(String file){
        try{
            mLogger = new FileOutputStream(new File(file));
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
    static public void logInfo(String info){
        SimpleDateFormat formatter= new SimpleDateFormat("[yyyy-MM-dd HH:mm:ss] ");
        Date date = new Date(System.currentTimeMillis());
        String time = formatter.format(date);
        try {
            mLogger.write(time.getBytes());
            if(info != null)
                mLogger.write(info.getBytes());
            mLogger.write("\r\n".getBytes());
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
}
