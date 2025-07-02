public class LogEvent {
    public final String timestamp, system, logType, ip, username, status;
    public LogEvent(String timestamp, String system, String logType, String ip, String username, String status) {
        this.timestamp = timestamp;
        this.system = system;
        this.logType = logType;
        this.ip = ip;
        this.username = username;
        this.status = status;
    }
    public static LogEvent parse(String line) {
        String[] parts = line.split("\\s*\\|\\s*");
        if (parts.length == 4) {
            return new LogEvent(parts[0], parts[1], "", parts[2], "", parts[3]);
        }
        if (parts.length == 6) {
            return new LogEvent(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]);
        }
        return null;
    }
}