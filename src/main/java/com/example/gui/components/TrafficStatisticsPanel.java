package com.example.gui.components;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.Map;

public class TrafficStatisticsPanel extends JPanel {
    private JTextArea statsArea;
    private JLabel lastUpdateLabel;
    private JLabel headerLabel;
    private AtomicInteger tcpCount = new AtomicInteger(0);
    private AtomicInteger udpCount = new AtomicInteger(0);
    private AtomicInteger httpCount = new AtomicInteger(0);
    private AtomicInteger httpsCount = new AtomicInteger(0);
    private AtomicInteger alertCount = new AtomicInteger(0);

    public TrafficStatisticsPanel() {
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
        headerLabel = new JLabel("Traffic Statistics");
        headerLabel.setFont(new Font("Segoe UI", Font.BOLD, 20));
        headerLabel.setForeground(new Color(33, 97, 140)); // blue accent
        headerLabel.setBorder(new MatteBorder(0, 0, 2, 0, new Color(33, 97, 140))); // thin blue underline

        statsArea = new JTextArea();
        statsArea.setEditable(false);
        statsArea.setFont(new Font("Segoe UI", Font.PLAIN, 15));
        statsArea.setBackground(new Color(248, 249, 251));
        statsArea.setForeground(new Color(30, 30, 30));
        statsArea.setMargin(new Insets(8, 8, 8, 8));
        statsArea.setBorder(BorderFactory.createEmptyBorder());

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

        JScrollPane statsScroll = new JScrollPane(statsArea);
        statsScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        statsScroll.setBorder(BorderFactory.createEmptyBorder());
        statsScroll.getViewport().setBackground(new Color(248, 249, 251));

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
        stats.append("TCP Traffic:    ").append(tcpCount.get()).append("\n");
        stats.append("UDP Traffic:    ").append(udpCount.get()).append("\n");
        stats.append("HTTP Traffic:   ").append(httpCount.get()).append("\n");
        stats.append("HTTPS Traffic:  ").append(httpsCount.get()).append("\n");
        stats.append("Alerts:         ").append(alertCount.get()).append("\n");

        statsArea.setText(stats.toString());
        lastUpdateLabel.setText("Last Update: " + java.time.LocalTime.now().toString());
    }

    public void reset() {
        tcpCount.set(0);
        udpCount.set(0);
        httpCount.set(0);
        httpsCount.set(0);
        alertCount.set(0);
        updateDisplay();
    }

    public JLabel getHeaderLabel() { return headerLabel; }
    public JTextArea getStatsArea() { return statsArea; }
    public JLabel getLastUpdateLabel() { return lastUpdateLabel; }
} 