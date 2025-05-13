package com.example.gui.components;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;

public class RLStatisticsPanel extends JPanel {
    private JTextArea rlStatsArea;
    private JLabel lastUpdateLabel;
    private JLabel headerLabel;
    private Queue<Double> recentAccuracies = new LinkedList<>();
    private static final int ACCURACY_WINDOW = 100;
    private double overallAccuracy = 0.0;
    private int allowedCount = 0;
    private int blockedCount = 0;

    public RLStatisticsPanel() {
        setLayout(new BorderLayout(0, 12));
        setBackground(Color.WHITE);
        setBorder(new CompoundBorder(
            new LineBorder(new Color(230, 230, 230), 1, true), // subtle gray border
            new EmptyBorder(18, 18, 18, 18)
        ));
        initializeComponents();
        setupLayout();
    }

    private void initializeComponents() {
        headerLabel = new JLabel("RL Statistics");
        headerLabel.setFont(new Font("Segoe UI", Font.BOLD, 20));
        headerLabel.setForeground(new Color(33, 97, 140)); // blue accent
        headerLabel.setBorder(new MatteBorder(0, 0, 2, 0, new Color(33, 97, 140))); // thin blue underline

        rlStatsArea = new JTextArea();
        rlStatsArea.setEditable(false);
        rlStatsArea.setFont(new Font("Segoe UI", Font.PLAIN, 15));
        rlStatsArea.setBackground(new Color(248, 249, 251));
        rlStatsArea.setForeground(new Color(30, 30, 30));
        rlStatsArea.setMargin(new Insets(8, 8, 8, 8));
        rlStatsArea.setBorder(BorderFactory.createEmptyBorder());

        lastUpdateLabel = new JLabel("Last Update: Never");
        lastUpdateLabel.setFont(new Font("Segoe UI", Font.ITALIC, 12));
        lastUpdateLabel.setForeground(new Color(120, 144, 156));
        lastUpdateLabel.setBorder(new EmptyBorder(0, 0, 0, 0));
    }

    private void setupLayout() {
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setOpaque(false);
        headerPanel.add(headerLabel, BorderLayout.WEST);
        headerPanel.add(lastUpdateLabel, BorderLayout.EAST);

        JScrollPane statsScroll = new JScrollPane(rlStatsArea);
        statsScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        statsScroll.setBorder(BorderFactory.createEmptyBorder());
        statsScroll.getViewport().setBackground(new Color(248, 249, 251));

        add(headerPanel, BorderLayout.NORTH);
        add(statsScroll, BorderLayout.CENTER);
    }

    public void updateRLStats(Map<String, Object> rlStats) {
        if (rlStats == null) return;
        allowedCount = (int) rlStats.getOrDefault("allowedCount", 0);
        blockedCount = (int) rlStats.getOrDefault("blockedCount", 0);
        overallAccuracy = Double.parseDouble(rlStats.getOrDefault("accuracy", 0.0).toString());

        double currentAccuracy = overallAccuracy;
        recentAccuracies.offer(currentAccuracy);
        if (recentAccuracies.size() > ACCURACY_WINDOW) {
            recentAccuracies.poll();
        }

        double realTimeAccuracy = recentAccuracies.stream()
            .mapToDouble(Double::doubleValue)
            .average()
            .orElse(0.0);

        StringBuilder stats = new StringBuilder();
        stats.append("Allowed packets: ").append(allowedCount).append("\n");
        stats.append("Blocked packets: ").append(blockedCount).append("\n");
        stats.append("Overall Accuracy: ").append(String.format("%.2f", overallAccuracy)).append("%\n");
        stats.append("Real-time Accuracy: ").append(String.format("%.2f", realTimeAccuracy)).append("%\n");

        stats.append("\nAccuracy Status:\n");
        stats.append("---------------\n");
        if (realTimeAccuracy >= 90) {
            stats.append("🟢 Excellent real-time performance\n");
        } else if (realTimeAccuracy >= 75) {
            stats.append("🟡 Good real-time performance\n");
        } else {
            stats.append("🔴 Needs attention\n");
        }

        rlStatsArea.setText(stats.toString());
        lastUpdateLabel.setText("Last Update: " + java.time.LocalTime.now().toString());
    }

    public void reset() {
        allowedCount = 0;
        blockedCount = 0;
        overallAccuracy = 0.0;
        recentAccuracies.clear();
        rlStatsArea.setText("");
        lastUpdateLabel.setText("Last Update: Never");
    }
} 