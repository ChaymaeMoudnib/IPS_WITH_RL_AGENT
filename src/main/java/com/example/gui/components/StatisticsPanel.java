package com.example.gui.components;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.LinkedList;
import java.util.Queue;

public class StatisticsPanel extends JPanel {
    private JTextArea statsArea;
    private JLabel lastUpdateLabel;
    private AtomicInteger tcpCount = new AtomicInteger(0);
    private AtomicInteger udpCount = new AtomicInteger(0);
    private AtomicInteger httpCount = new AtomicInteger(0);
    private AtomicInteger httpsCount = new AtomicInteger(0);
    private AtomicInteger alertCount = new AtomicInteger(0);
    private Queue<Double> recentAccuracies = new LinkedList<>();
    private static final int ACCURACY_WINDOW = 100; // Track last 100 decisions for real-time accuracy
    private double overallAccuracy = 0.0;

    public StatisticsPanel() {
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("Statistics"),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));
        setBackground(new Color(245, 245, 245));
        initializeComponents();
        setupLayout();
    }

    private void initializeComponents() {
        statsArea = new JTextArea();
        statsArea.setEditable(false);
        statsArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        statsArea.setBackground(new Color(250, 250, 250));
        statsArea.setForeground(new Color(50, 50, 50));
        statsArea.setMargin(new Insets(5, 5, 5, 5));

        lastUpdateLabel = new JLabel("Last Update: Never");
        lastUpdateLabel.setFont(new Font("Arial", Font.ITALIC, 10));
        lastUpdateLabel.setForeground(new Color(100, 100, 100));
    }

    private void setupLayout() {
        JScrollPane statsScroll = new JScrollPane(statsArea);
        statsScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        statsScroll.setBorder(BorderFactory.createLineBorder(new Color(200, 200, 200)));

        JPanel headerPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        headerPanel.setBackground(new Color(245, 245, 245));
        headerPanel.add(lastUpdateLabel);

        add(headerPanel, BorderLayout.NORTH);
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
        stats.append("Traffic Statistics\n");
        stats.append("=================\n\n");
        stats.append("TCP Traffic:    ").append(tcpCount.get()).append("\n");
        stats.append("UDP Traffic:    ").append(udpCount.get()).append("\n");
        stats.append("HTTP Traffic:   ").append(httpCount.get()).append("\n");
        stats.append("HTTPS Traffic:  ").append(httpsCount.get()).append("\n");
        stats.append("Alerts:         ").append(alertCount.get()).append("\n");

        statsArea.setText(stats.toString());
        lastUpdateLabel.setText("Last Update: " + java.time.LocalTime.now().toString());
    }

    public void updateRLStats(Map<String, Object> rlStats) {
        // Update overall accuracy
        overallAccuracy = Double.parseDouble(rlStats.get("accuracy").toString());
        
        // Update real-time accuracy
        double currentAccuracy = Double.parseDouble(rlStats.get("accuracy").toString());
        recentAccuracies.offer(currentAccuracy);
        if (recentAccuracies.size() > ACCURACY_WINDOW) {
            recentAccuracies.poll();
        }
        
        // Calculate real-time accuracy
        double realTimeAccuracy = recentAccuracies.stream()
            .mapToDouble(Double::doubleValue)
            .average()
            .orElse(0.0);

        StringBuilder stats = new StringBuilder();
        stats.append("Traffic Statistics\n");
        stats.append("=================\n\n");
        stats.append("TCP Traffic:    ").append(tcpCount.get()).append("\n");
        stats.append("UDP Traffic:    ").append(udpCount.get()).append("\n");
        stats.append("HTTP Traffic:   ").append(httpCount.get()).append("\n");
        stats.append("HTTPS Traffic:  ").append(httpsCount.get()).append("\n");
        stats.append("Alerts:         ").append(alertCount.get()).append("\n\n");

        stats.append("RL Statistics\n");
        stats.append("============\n\n");
        stats.append("Allowed packets: ").append(rlStats.get("allowedCount")).append("\n");
        stats.append("Blocked packets: ").append(rlStats.get("blockedCount")).append("\n");
        stats.append("Overall Accuracy: ").append(String.format("%.2f", overallAccuracy)).append("%\n");
        stats.append("Real-time Accuracy: ").append(String.format("%.2f", realTimeAccuracy)).append("%\n");

        // Add color-coded accuracy indicators
        stats.append("\nAccuracy Status:\n");
        stats.append("---------------\n");
        if (realTimeAccuracy >= 90) {
            stats.append("🟢 Excellent real-time performance\n");
        } else if (realTimeAccuracy >= 75) {
            stats.append("🟡 Good real-time performance\n");
        } else {
            stats.append("🔴 Needs attention\n");
        }

        statsArea.setText(stats.toString());
        lastUpdateLabel.setText("Last Update: " + java.time.LocalTime.now().toString());
    }

    public void reset() {
        tcpCount.set(0);
        udpCount.set(0);
        httpCount.set(0);
        httpsCount.set(0);
        alertCount.set(0);
        recentAccuracies.clear();
        overallAccuracy = 0.0;
        updateDisplay();
    }
} 