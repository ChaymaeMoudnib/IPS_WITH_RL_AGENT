package com.example.gui.components;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

public class ControlPanel extends JPanel {
    private JComboBox<String> interfaceComboBox;
    private JComboBox<String> protocolComboBox;
    private JButton buttonStart;
    private JButton buttonStop;
    private JButton buttonExit;
    private JCheckBox rlEnabledCheckbox;
    private JLabel statusLabel;
    private String selectedProtocol = "ALL";
    private Map<String, String> interfaceMap = new HashMap<>();

    public ControlPanel() {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("Control Panel"),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));
        initializeComponents();
        setupLayout();
        loadNetworkInterfaces();
    }

    private void initializeComponents() {
        // Style the combo boxes
        interfaceComboBox = new JComboBox<>();
        protocolComboBox = new JComboBox<>(new String[] { "ALL", "TCP", "UDP", "HTTP", "HTTPS" });
        interfaceComboBox.setPreferredSize(new Dimension(250, 25));
        protocolComboBox.setPreferredSize(new Dimension(100, 25));

        // Create buttons with icons
        buttonStart = createButton("Start Capture", "play.png");
        buttonStop = createButton("Stop Capture", "stop.png");
        buttonExit = createButton("Exit", "exit.png");
        rlEnabledCheckbox = new JCheckBox("Enable RL IP Control");
        statusLabel = new JLabel("Status: Ready");

        // Style the status label
        statusLabel.setFont(new Font("Arial", Font.BOLD, 12));
        statusLabel.setForeground(new Color(0, 100, 0));

        buttonStop.setEnabled(false);
        rlEnabledCheckbox.setSelected(false);
    }

    private JButton createButton(String text, String iconName) {
        JButton button = new JButton(text);
        try {
            ImageIcon icon = new ImageIcon(getClass().getResource("/icons/" + iconName));
            Image scaledImage = icon.getImage().getScaledInstance(16, 16, Image.SCALE_SMOOTH);
            button.setIcon(new ImageIcon(scaledImage));
        } catch (Exception e) {
            // Icon not found, continue without it
        }
        button.setFocusPainted(false);
        button.setBackground(new Color(240, 240, 240));
        button.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(200, 200, 200)),
            BorderFactory.createEmptyBorder(5, 10, 5, 10)
        ));
        return button;
    }

    private void setupLayout() {
        JPanel controlsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        controlsPanel.setBackground(new Color(245, 245, 245));

        // Network Interface selection
        JPanel interfacePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        interfacePanel.setBackground(new Color(245, 245, 245));
        interfacePanel.add(new JLabel("Network Interface:"));
        interfacePanel.add(interfaceComboBox);
        controlsPanel.add(interfacePanel);

        // Protocol selection
        JPanel protocolPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        protocolPanel.setBackground(new Color(245, 245, 245));
        protocolPanel.add(new JLabel("Protocol:"));
        protocolPanel.add(protocolComboBox);
        controlsPanel.add(protocolPanel);

        // Buttons
        controlsPanel.add(buttonStart);
        controlsPanel.add(buttonStop);
        controlsPanel.add(buttonExit);
        controlsPanel.add(rlEnabledCheckbox);
        controlsPanel.add(statusLabel);

        add(controlsPanel);
    }

    private void loadNetworkInterfaces() {
        try {
            List<PcapNetworkInterface> devices = Pcaps.findAllDevs();
            for (PcapNetworkInterface device : devices) {
                String displayName = device.getName() + " (" + device.getDescription() + ")";
                interfaceComboBox.addItem(displayName);
                interfaceMap.put(displayName, device.getName());
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error loading network interfaces: " + e.getMessage());
        }
    }

    public String getSelectedInterface() {
        String displayName = (String) interfaceComboBox.getSelectedItem();
        return displayName != null ? interfaceMap.get(displayName) : null;
    }

    // Getters for components
    public JComboBox<String> getInterfaceComboBox() { return interfaceComboBox; }
    public JComboBox<String> getProtocolComboBox() { return protocolComboBox; }
    public JButton getButtonStart() { return buttonStart; }
    public JButton getButtonStop() { return buttonStop; }
    public JButton getButtonExit() { return buttonExit; }
    public JCheckBox getRlEnabledCheckbox() { return rlEnabledCheckbox; }
    public JLabel getStatusLabel() { return statusLabel; }
    public String getSelectedProtocol() { return selectedProtocol; }

    // Setters
    public void setSelectedProtocol(String protocol) { this.selectedProtocol = protocol; }
    public void setStatus(String status) { 
        statusLabel.setText("Status: " + status);
        if (status.equals("Capturing...")) {
            statusLabel.setForeground(new Color(0, 100, 0));
        } else if (status.equals("Stopped")) {
            statusLabel.setForeground(new Color(150, 0, 0));
        } else {
            statusLabel.setForeground(new Color(0, 0, 150));
        }
    }
} 