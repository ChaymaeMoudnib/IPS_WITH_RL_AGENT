package com.example.gui.components;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.util.Map;

public class PacketDisplayPanel extends JPanel {
    private JTextArea packetArea;
    private JLabel packetCountLabel;
    private JLabel headerLabel;
    private int packetCount = 0;

    public PacketDisplayPanel() {
        setLayout(new BorderLayout(0, 12));
        setBackground(Color.WHITE);
        setBorder(new CompoundBorder(
            new LineBorder(new Color(230, 230, 230), 1, true),
            new EmptyBorder(18, 18, 18, 18)
        ));
        initializeComponents();
        setupLayout();
    }

    private void initializeComponents() {
        headerLabel = new JLabel("Captured Packets");
        headerLabel.setFont(new Font("Segoe UI", Font.BOLD, 20));
        headerLabel.setForeground(new Color(33, 97, 140));
        headerLabel.setBorder(new MatteBorder(0, 0, 2, 0, new Color(33, 97, 140)));

        packetArea = new JTextArea();
        packetArea.setEditable(false);
        packetArea.setFont(new Font("Segoe UI", Font.PLAIN, 15));
        packetArea.setBackground(new Color(248, 249, 251));
        packetArea.setForeground(new Color(30, 30, 30));
        packetArea.setMargin(new Insets(8, 8, 8, 8));
        packetArea.setBorder(BorderFactory.createEmptyBorder());

        packetCountLabel = new JLabel("Packets: 0");
        packetCountLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));
        packetCountLabel.setForeground(new Color(0, 150, 0));
        packetCountLabel.setBorder(new EmptyBorder(0, 0, 0, 0));
    }

    private void setupLayout() {
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setOpaque(false);
        headerPanel.add(headerLabel, BorderLayout.WEST);
        headerPanel.add(packetCountLabel, BorderLayout.EAST);

        JScrollPane packetScroll = new JScrollPane(packetArea);
        packetScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        packetScroll.setBorder(BorderFactory.createEmptyBorder());
        packetScroll.getViewport().setBackground(new Color(248, 249, 251));

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