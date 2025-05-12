package com.example.gui.components;

import javax.swing.*;
import java.awt.*;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public class StatisticsPanel extends JPanel {
    private JTextArea statsArea;
    private AtomicInteger tcpCount = new AtomicInteger(0);
    private AtomicInteger udpCount = new AtomicInteger(0);
    private AtomicInteger httpCount = new AtomicInteger(0);
    private AtomicInteger httpsCount = new AtomicInteger(0);
    private AtomicInteger alertCount = new AtomicInteger(0);

    public StatisticsPanel() {
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createTitledBorder("Statistics"));
        initializeComponents();
        setupLayout();
    }

    private void initializeComponents() {
        statsArea = new JTextArea();
        statsArea.setEditable(false);
        statsArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        statsArea.setBackground(new Color(245, 245, 245));
    }

    private void setupLayout() {
        JScrollPane statsScroll = new JScrollPane(statsArea);
        add(statsScroll, BorderLayout.CENTER);
    }

    public void updateStatistics(Map<String, String> packetData) {
        String protocol = packetData.get("protocol");
        if (protocol == null) return;

        switch (protocol.toUpperCase()) {
            case "TCP":
                tcpCount.incrementAndGet();
                break;
            case "UDP":
                udpCount.incrementAndGet();
                break;
            case "HTTP":
                httpCount.incrementAndGet();
                tcpCount.incrementAndGet();
                break;
            case "HTTPS":
                httpsCount.incrementAndGet();
                tcpCount.incrementAndGet();
                break;
        }

        updateDisplay();
    }

    public void incrementAlertCount() {
        alertCount.incrementAndGet();
        updateDisplay();
    }

    private void updateDisplay() {
        StringBuilder stats = new StringBuilder();
        stats.append("Traffic Statistics:\n");
        stats.append("TCP Traffic: ").append(tcpCount.get()).append("\n");
        stats.append("UDP Traffic: ").append(udpCount.get()).append("\n");
        stats.append("HTTP Traffic: ").append(httpCount.get()).append("\n");
        stats.append("HTTPS Traffic: ").append(httpsCount.get()).append("\n");
        stats.append("Alerts: ").append(alertCount.get()).append("\n");

        statsArea.setText(stats.toString());
    }

    public void updateRLStats(Map<String, Object> rlStats) {
        StringBuilder stats = new StringBuilder();
        stats.append("Traffic Statistics:\n");
        stats.append("TCP Traffic: ").append(tcpCount.get()).append("\n");
        stats.append("UDP Traffic: ").append(udpCount.get()).append("\n");
        stats.append("HTTP Traffic: ").append(httpCount.get()).append("\n");
        stats.append("HTTPS Traffic: ").append(httpsCount.get()).append("\n");
        stats.append("Alerts: ").append(alertCount.get()).append("\n\n");

        stats.append("RL Statistics:\n");
        stats.append("Allowed packets: ").append(rlStats.get("allowedCount")).append("\n");
        stats.append("Blocked packets: ").append(rlStats.get("blockedCount")).append("\n");
        stats.append("Accuracy: ").append(rlStats.get("accuracy")).append("\n");

        statsArea.setText(stats.toString());
    }

    public void reset() {
        tcpCount.set(0);
        udpCount.set(0);
        httpCount.set(0);
        httpsCount.set(0);
        alertCount.set(0);
        updateDisplay();
    }
} 