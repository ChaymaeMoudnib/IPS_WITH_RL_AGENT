package com.example.gui.components;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import com.example.detection.Alert;
import com.example.detection.Severity;

public class LogPanel extends JPanel {
    private JTextPane logArea;
    private static final String LOG_DIR = "logs";
    private FileWriter logWriter;
    private SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public LogPanel() {
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createTitledBorder("Logs & Alerts"));
        initializeComponents();
        setupLayout();
        createLogDirectory();
    }

    private void initializeComponents() {
        logArea = new JTextPane();
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        logArea.setBackground(new Color(250, 250, 250));
    }

    private void setupLayout() {
        JScrollPane logScroll = new JScrollPane(logArea);
        add(logScroll, BorderLayout.CENTER);
    }

    private void createLogDirectory() {
        File dir = new File(LOG_DIR);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        try {
            String logFile = LOG_DIR + "/ids_" + new SimpleDateFormat("yyyy-MM-dd").format(new Date()) + ".log";
            logWriter = new FileWriter(logFile, true);
        } catch (IOException e) {
            appendText("Error creating log file: " + e.getMessage() + "\n");
        }
    }

    public void appendText(String text) {
        try {
            logArea.getDocument().insertString(logArea.getDocument().getLength(), text, null);
            logArea.setCaretPosition(logArea.getDocument().getLength());
        } catch (javax.swing.text.BadLocationException e) {
            e.printStackTrace();
        }
    }

    public void displayAlert(Alert alert) {
        if (alert == null) return;

        StringBuilder alertMessage = new StringBuilder();
        alertMessage.append(String.format("[%s] [%s] ALERT: %s\n",
                dateFormat.format(new Date()),
                alert.getSeverity(),
                alert.getMessage()));

        Map<String, String> packetData = alert.getPacketData();
        if (packetData != null) {
            alertMessage.append(String.format("Source: %s:%s\n",
                    packetData.get("srcIP"),
                    packetData.get("srcPort")));
            alertMessage.append(String.format("Destination: %s:%s\n",
                    packetData.get("destIP"),
                    packetData.get("destPort")));
            alertMessage.append(String.format("Protocol: %s\n",
                    packetData.get("protocol")));
            alertMessage.append(String.format("Data: %s\n",
                    packetData.get("data")));
        }

        alertMessage.append("-------------------\n");
        appendColoredAlert(alertMessage.toString(), alert.getSeverity().toString());
    }

    private void appendColoredAlert(String text, String severity) {
        Color color;
        switch (severity.toUpperCase()) {
            case "CRITICAL":
                color = new Color(200, 0, 0);
                break;
            case "HIGH":
                color = new Color(255, 60, 60);
                break;
            case "MEDIUM":
                color = new Color(255, 140, 0);
                break;
            case "LOW":
                color = new Color(255, 200, 0);
                break;
            default:
                color = new Color(0, 0, 0);
        }

        javax.swing.text.Style style = ((javax.swing.text.StyledDocument) logArea.getDocument())
                .addStyle("Alert Style", null);
        javax.swing.text.StyleConstants.setForeground(style, color);

        try {
            ((javax.swing.text.StyledDocument) logArea.getDocument()).insertString(
                    logArea.getDocument().getLength(), text, style);
            logArea.setCaretPosition(logArea.getDocument().getLength());
        } catch (javax.swing.text.BadLocationException e) {
            e.printStackTrace();
        }
    }

    public void clear() {
        logArea.setText("");
    }

    public void close() {
        try {
            if (logWriter != null) {
                logWriter.close();
            }
        } catch (IOException e) {
            System.err.println("Error closing log file: " + e.getMessage());
        }
    }
} 