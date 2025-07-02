import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.*;

public class LogAnalyzer {
    private final boolean parallel;

    public LogAnalyzer(boolean parallel) {
        this.parallel = parallel;
    }

    public void runAnalysis(String firewallDir, String winsecDir, String dbDir, String outputCsv) throws IOException {
        System.out.println("Step 1: Processing firewall logs...");
        Set<String> permittedIps = ConcurrentHashMap.newKeySet();
        Stream<Path> fwStream = parallel ? Files.walk(Paths.get(firewallDir)).parallel() : Files.walk(Paths.get(firewallDir));
        fwStream.filter(Files::isRegularFile)
                .filter(p -> p.toString().endsWith(".log"))
                .forEach(file -> {
                    try (BufferedReader reader = Files.newBufferedReader(file)) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            if (!parallel) {
                                try { Thread.sleep(2); } catch (InterruptedException e) {}
                            }
                            LogEvent evt = LogEvent.parse(line);
                            if (evt == null) continue;
                            if ("FIREWALL".equalsIgnoreCase(evt.system) && evt.status.equalsIgnoreCase("TRAFFIC PERMIT")) {
                                permittedIps.add(evt.ip);
                            }
                        }
                    } catch (Exception e) {}
                });

        System.out.println("Step 2: Processing Windows logs...");
        Map<String, Map<String, ActivityRecord>> ipUserActivities = new ConcurrentHashMap<>();
        Stream<Path> winsecStream = parallel ? Files.walk(Paths.get(winsecDir)).parallel() : Files.walk(Paths.get(winsecDir));
        winsecStream.filter(Files::isRegularFile)
                .filter(p -> p.toString().endsWith(".log"))
                .forEach(file -> {
                    try (BufferedReader reader = Files.newBufferedReader(file)) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            if (!parallel) {
                                try { Thread.sleep(20); } catch (InterruptedException e) {}
                            }
                            LogEvent evt = LogEvent.parse(line);
                            if (evt == null || evt.ip == null || evt.username == null) continue;
                            if (!permittedIps.contains(evt.ip)) continue;

                            // Track login
                            if ("WINSEC".equalsIgnoreCase(evt.system) && "SECURITY".equalsIgnoreCase(evt.logType)
                                    && !evt.username.isEmpty()
                                    && evt.status.equalsIgnoreCase("LOGIN SUCCESS")) {
                                ipUserActivities
                                        .computeIfAbsent(evt.ip, k -> new ConcurrentHashMap<>())
                                        .computeIfAbsent(evt.username, u -> new ActivityRecord(evt.ip, evt.username, evt.timestamp));
                            }
                            // Track apps
                            if ("WINSEC".equalsIgnoreCase(evt.system) && "APPLICATION".equalsIgnoreCase(evt.logType)
                                    && !evt.username.isEmpty()
                                    && evt.status.startsWith("Launched:")) {
                                Map<String, ActivityRecord> userMap = ipUserActivities.get(evt.ip);
                                if (userMap != null && userMap.containsKey(evt.username)) {
                                    userMap.get(evt.username).applications.add(evt.status.substring("Launched:".length()).trim());
                                }
                            }
                        }
                    } catch (Exception e) {}
                });

        System.out.println("Step 3: Processing database logs...");
        Stream<Path> dbStream = parallel ? Files.walk(Paths.get(dbDir)).parallel() : Files.walk(Paths.get(dbDir));
        dbStream.filter(Files::isRegularFile)
                .filter(p -> p.toString().endsWith(".log"))
                .forEach(file -> {
                    try (BufferedReader reader = Files.newBufferedReader(file)) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            if (!parallel) {
                                try { Thread.sleep(20); } catch (InterruptedException e) {}
                            }
                            LogEvent evt = LogEvent.parse(line);
                            if (evt == null || evt.ip == null || evt.username == null) continue;
                            if (!permittedIps.contains(evt.ip)) continue;
                            if ("DB".equalsIgnoreCase(evt.system) && "DATABASE".equalsIgnoreCase(evt.logType)) {
                                Map<String, ActivityRecord> userMap = ipUserActivities.get(evt.ip);
                                if (userMap != null && userMap.containsKey(evt.username)) {
                                    userMap.get(evt.username).dbEvents.add(evt.status + " (" + evt.timestamp + ")");
                                }
                            }
                        }
                    } catch (Exception e) {}
                });

        System.out.println("Writing result.csv (user activity sessions)...");
        try (PrintWriter out = new PrintWriter(outputCsv)) {
            out.println("IP,User,Login Time,Applications,DB_Logins");
            for (var ipEntry : ipUserActivities.entrySet()) {
                for (var userEntry : ipEntry.getValue().entrySet()) {
                    ActivityRecord rec = userEntry.getValue();
                    // Only output if user has any application launched OR DB activity
                    if (!rec.applications.isEmpty() || !rec.dbEvents.isEmpty()) {
                        out.printf("%s,%s,%s,\"%s\",\"%s\"%n",
                                rec.ip, rec.user, rec.loginTime,
                                String.join(";", rec.applications),
                                String.join(";", rec.dbEvents));
                    }
                }
            }
        }

        System.out.println("Writing suspicious.csv (security anomalies)...");
        try (PrintWriter out = new PrintWriter("output/suspicious.csv")) {
            out.println("Type,IP,User,Details");

            // 1. IPs with logins for multiple users (spray/movement)
            for (var ipEntry : ipUserActivities.entrySet()) {
                Set<String> users = ipEntry.getValue().keySet();
                if (users.size() > 2) {
                    out.printf("SprayAttempt,%s,,Users: %s%n", ipEntry.getKey(), String.join(";", users));
                }
            }

            // 2. Users logging in from Different IPs
            Map<String, Set<String>> userToIps = new HashMap<>();
            for (var ipEntry : ipUserActivities.entrySet()) {
                for (String user : ipEntry.getValue().keySet()) {
                    userToIps.computeIfAbsent(user, k -> new HashSet<>()).add(ipEntry.getKey());
                }
            }
            for (var entry : userToIps.entrySet()) {
                if (entry.getValue().size() > 2) {
                    out.printf("MultiIP,,%s,IPs: %s%n", entry.getKey(), String.join(";", entry.getValue()));
                }
            }

            // 3. Multiple DB login failure (only report if user has any application or DB activity)
            for (var ipEntry : ipUserActivities.entrySet()) {
                for (var userEntry : ipEntry.getValue().entrySet()) {
                    ActivityRecord rec = userEntry.getValue();
                    if (!rec.applications.isEmpty() || !rec.dbEvents.isEmpty()) {
                        for (String dbEvent : rec.dbEvents) {
                            if (dbEvent.contains("FAILURE")) {
                                out.printf("DBFailure,%s,%s,%s%n", rec.ip, rec.user, dbEvent);
                            }
                        }
                    }
                }
            }
        }
        System.out.println("All analysis complete! See output/result.csv and output/suspicious.csv");
    }
}
