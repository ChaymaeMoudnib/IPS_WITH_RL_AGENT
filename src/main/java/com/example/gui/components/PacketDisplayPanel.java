package com.example.gui.components;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.util.Map;

public class PacketDisplayPanel extends JPanel {
    private JTextArea packetArea;
    private JLabel packetCountLabel;
    private int packetCount = 0;

    public PacketDisplayPanel() {
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("Captured Packets"),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));
        setBackground(new Color(245, 245, 245));
        initializeComponents();
        setupLayout();
    }

    private void initializeComponents() {
        packetArea = new JTextArea();
        packetArea.setEditable(false);
        packetArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        packetArea.setBackground(new Color(250, 250, 250));
        packetArea.setForeground(new Color(50, 50, 50));
        packetArea.setMargin(new Insets(5, 5, 5, 5));

        packetCountLabel = new JLabel("Packets: 0");
        packetCountLabel.setFont(new Font("Arial", Font.BOLD, 12));
        packetCountLabel.setForeground(new Color(0, 100, 0));
    }

    private void setupLayout() {
        JScrollPane packetScroll = new JScrollPane(packetArea);
        packetScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        packetScroll.setBorder(BorderFactory.createLineBorder(new Color(200, 200, 200)));
        
        JPanel headerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        headerPanel.setBackground(new Color(245, 245, 245));
        headerPanel.add(packetCountLabel);
        
        add(headerPanel, BorderLayout.NORTH);
        add(packetScroll, BorderLayout.CENTER);
    }

    public void appendPacket(Map<String, String> packetData) {
        if (packetData != null) {
            StringBuilder sb = new StringBuilder();
            sb.append("Packet #").append(++packetCount).append("\n");
            sb.append("----------------------------------------\n");
            for (Map.Entry<String, String> entry : packetData.entrySet()) {
                sb.append(String.format("%-15s: %s\n", entry.getKey(), entry.getValue()));
            }
            sb.append("----------------------------------------\n\n");
            
            packetArea.append(sb.toString());
            packetArea.setCaretPosition(packetArea.getDocument().getLength());
            packetCountLabel.setText("Packets: " + packetCount);
        }
    }

    public void clear() {
        packetArea.setText("");
        packetCount = 0;
        packetCountLabel.setText("Packets: 0");
    }

    public JTextArea getPacketArea() {
        return packetArea;
    }
} 