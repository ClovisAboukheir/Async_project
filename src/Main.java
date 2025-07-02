import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.*;

public class Main {
    public static void main(String[] args) throws java.io.IOException {
        System.out.println("==== Java Parallel Log ETL ====");
        if (args.length != 4) {
            System.out.println("Usage: java Main <firewall_folder> <winsec_folder> <dblayer_folder> <mode:parallel|sequential>");
            System.exit(1);
        }
        String firewallFolder = args[0];
        String winsecFolder = args[1];
        String dbFolder = args[2];
        boolean parallel = args[3].equalsIgnoreCase("parallel");
        System.out.printf("Starting log analysis in %s mode...\n", parallel ? "Parallel" : "Sequential");
        System.out.println("Processing folders:");
        System.out.println(" - Firewall logs: " + firewallFolder);
        System.out.println(" - Windows logs:  " + winsecFolder);
        System.out.println(" - Database logs: " + dbFolder);
        LogAnalyzer analyzer = new LogAnalyzer(parallel);
        long startAll = System.nanoTime();
        analyzer.runAnalysis(firewallFolder, winsecFolder, dbFolder, "output/result.csv");
        long endAll = System.nanoTime();
        System.out.printf("Total ETL Time (%s): %.3fs\n", parallel ? "Parallel" : "Sequential", (endAll - startAll) / 1e9);
        System.out.println("Analysis complete!");
        System.out.println("Check 'output/result.csv' for the main results.");
        System.out.println("Check 'output/suspicious.csv' for suspicious findings.");
        System.out.println("===============================");
    }
}
