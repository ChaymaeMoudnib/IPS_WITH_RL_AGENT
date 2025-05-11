package com.example.logging;

import com.example.detection.Alert;
import com.example.detection.AlertType;
import com.example.detection.Severity;
import com.example.util.Rule;
import com.example.util.EmailService;
import java.io.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AlertLogger {
    private static final String LOG_DIR = "logs";
    private FileWriter logWriter;
    private final SimpleDateFormat dateFormat;
    private final ExecutorService executor;
    private static final int MAX_LOG_SIZE = 10 * 1024 * 1024; // 10MB
    private final EmailService emailService;

    public AlertLogger() throws IOException {
        createLogDirectory();
        String logFile = LOG_DIR + "/ids_" + new SimpleDateFormat("yyyy-MM-dd").format(new Date()) + ".log";
        this.logWriter = new FileWriter(logFile, true);
        this.dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        this.executor = Executors.newSingleThreadExecutor();
        this.emailService = EmailService.getInstance();
    }

    private void createLogDirectory() {
        File dir = new File(LOG_DIR);
        if (!dir.exists()) {
            dir.mkdirs();
        }
    }

    public void logAlert(Rule rule, Map<String, String> packet) {
        String severity = rule.getOption("severity");
        String message = rule.getOption("msg");
        
        Alert alert = new Alert(
            AlertType.valueOf(severity.toUpperCase()),
            Severity.valueOf(severity.toUpperCase()),
            message,
            packet
        );
        
        logAlert(alert);
    }

    public void logAnomaly(Alert anomaly, Map<String, String> packet) {
        anomaly.setPacketData(packet);
        logAlert(anomaly);
    }

    private void logAlert(Alert alert) {
        executor.execute(() -> {
            try {
                String logEntry = formatLogEntry(alert);
                synchronized (logWriter) {
                    logWriter.write(logEntry);
                    logWriter.flush();
                    checkLogRotation();
                }

                // Send email for critical and high severity alerts
                if (alert.getSeverity() == Severity.CRITICAL || alert.getSeverity() == Severity.HIGH) {
                    emailService.sendAlertEmail(alert);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
    }

    private String formatLogEntry(Alert alert) {
        StringBuilder sb = new StringBuilder();
        sb.append("[")
          .append(dateFormat.format(new Date()))
          .append("] [")
          .append(alert.getSeverity())
          .append("] ")
          .append(alert.getType())
          .append(": ")
          .append(alert.getMessage())
          .append("\n");

        if (alert.getPacketData() != null) {
            sb.append("Packet Details:\n");
            for (Map.Entry<String, String> entry : alert.getPacketData().entrySet()) {
                sb.append("  ")
                  .append(entry.getKey())
                  .append(": ")
                  .append(entry.getValue())
                  .append("\n");
            }
        }
        sb.append("\n");
        return sb.toString();
    }

    private void checkLogRotation() throws IOException {
        File logFile = new File(logWriter.toString());
        if (logFile.length() > MAX_LOG_SIZE) {
            String newLogFile = LOG_DIR + "/ids_" + dateFormat.format(new Date()) + "_" + 
                              System.currentTimeMillis() + ".log";
            logWriter.close();
            this.logWriter = new FileWriter(newLogFile, true);
        }
    }

    public void close() {
        executor.shutdown();
        try {
            logWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
} 