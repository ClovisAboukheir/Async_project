import java.util.*;

public class ActivityRecord {
    public final String ip, user;
    public String loginTime = "";
    public final List<String> applications = new ArrayList<>();
    public final List<String> dbEvents = new ArrayList<>();
    public ActivityRecord(String ip, String user, String loginTime) {
        this.ip = ip; this.user = user; this.loginTime = loginTime;
    }
}
