package com.example.gui.components;

import javax.swing.*;
import java.awt.*;
import java.util.Map;

public class PacketDisplayPanel extends JPanel {
    private JTextArea packetArea;

    public PacketDisplayPanel() {
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createTitledBorder("Captured Packets"));
        initializeComponents();
        setupLayout();
    }

    private void initializeComponents() {
        packetArea = new JTextArea();
        packetArea.setEditable(false);
        packetArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        packetArea.setBackground(new Color(240, 240, 240));
    }

    private void setupLayout() {
        JScrollPane packetScroll = new JScrollPane(packetArea);
        packetScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        add(packetScroll, BorderLayout.CENTER);
    }

    public void appendPacket(Map<String, String> packetData) {
        if (packetData != null) {
            StringBuilder sb = new StringBuilder();
            sb.append("Packet Details:\n");
            for (Map.Entry<String, String> entry : packetData.entrySet()) {
                sb.append(String.format("  %s: %s\n", entry.getKey(), entry.getValue()));
            }
            packetArea.append(sb.toString() + "\n");
            packetArea.setCaretPosition(packetArea.getDocument().getLength());
        }
    }

    public void clear() {
        packetArea.setText("");
    }

    public JTextArea getPacketArea() {
        return packetArea;
    }
} 