package com.example.logging;

import com.example.detection.Alert;
import com.example.detection.AlertType;
import com.example.detection.Severity;
import com.example.util.Rule;
import java.io.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.nio.file.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.Arrays;

public class AlertLogger {
    private static final Logger LOGGER = Logger.getLogger(AlertLogger.class.getName());
    private static final String LOG_DIR = "logs";
    private static final int MAX_LOG_SIZE = 10 * 1024 * 1024; // 10MB
    private static final int MAX_LOG_FILES = 10;
    
    private final SimpleDateFormat dateFormat;
    private final ExecutorService executor;
    private final AtomicLong currentLogSize;
    private FileWriter logWriter;
    private String currentLogFile;

    public AlertLogger() throws IOException {
        createLogDirectory();
        this.dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        this.executor = Executors.newSingleThreadExecutor();
        this.currentLogSize = new AtomicLong(0);
        initializeLogFile();
    }

    private void createLogDirectory() throws IOException {
        try {
            Files.createDirectories(Paths.get(LOG_DIR));
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to create log directory", e);
            throw e;
        }
    }

    private void initializeLogFile() throws IOException {
        currentLogFile = LOG_DIR + "/ids_" + new SimpleDateFormat("yyyy-MM-dd").format(new Date()) + ".log";
        this.logWriter = new FileWriter(currentLogFile, true);
        this.currentLogSize.set(new File(currentLogFile).length());
        cleanupOldLogs();
    }

    private void cleanupOldLogs() {
        try {
            File logDir = new File(LOG_DIR);
            File[] logFiles = logDir.listFiles((dir, name) -> name.startsWith("ids_") && name.endsWith(".log"));
            
            if (logFiles != null && logFiles.length > MAX_LOG_FILES) {
                Arrays.sort(logFiles, (f1, f2) -> Long.compare(f2.lastModified(), f1.lastModified()));
                for (int i = MAX_LOG_FILES; i < logFiles.length; i++) {
                    logFiles[i].delete();
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to cleanup old logs", e);
        }
    }

    public void logAlert(Rule rule, Map<String, String> packet) {
        try {
            String severity = rule.getOption("severity");
            String message = rule.getOption("msg");
            
            Alert alert = new Alert(
                AlertType.valueOf(severity.toUpperCase()),
                Severity.valueOf(severity.toUpperCase()),
                message,
                packet
            );
            
            logAlert(alert);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to log alert from rule", e);
        }
    }

    public void logAnomaly(Alert anomaly, Map<String, String> packet) {
        try {
            anomaly.setPacketData(packet);
            logAlert(anomaly);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to log anomaly", e);
        }
    }

    private void logAlert(Alert alert) {
        executor.execute(() -> {
            try {
                String logEntry = formatLogEntry(alert);
                synchronized (logWriter) {
                    logWriter.write(logEntry);
                    logWriter.flush();
                    currentLogSize.addAndGet(logEntry.getBytes().length);
                    
                    if (currentLogSize.get() > MAX_LOG_SIZE) {
                        rotateLog();
                    }
                }
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Failed to write log entry", e);
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
            alert.getPacketData().forEach((key, value) -> 
                sb.append("  ")
                  .append(key)
                  .append(": ")
                  .append(value)
                  .append("\n")
            );
        }
        sb.append("\n");
        return sb.toString();
    }

    private void rotateLog() throws IOException {
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String newLogFile = LOG_DIR + "/ids_" + timestamp + ".log";
        
        logWriter.close();
        this.logWriter = new FileWriter(newLogFile, true);
        this.currentLogFile = newLogFile;
        this.currentLogSize.set(0);
        
        cleanupOldLogs();
    }

    public void close() {
        executor.shutdown();
        try {
            if (logWriter != null) {
                logWriter.close();
            }
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Error closing log writer", e);
        }
    }
} 