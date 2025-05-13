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
    private JToggleButton darkModeToggle;

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
        interfaceComboBox.setPreferredSize(new Dimension(500, 25));
        protocolComboBox.setPreferredSize(new Dimension(100, 25));

        // Create buttons with icons
        buttonStart = createButton("Start Capture", "play.png");
        buttonStop = createButton("Stop Capture", "stop.png");
        buttonExit = createButton("Exit", "exit.png");
        rlEnabledCheckbox = new JCheckBox("Enable RL IP Control");
        statusLabel = new JLabel("Status: Ready");
        darkModeToggle = new JToggleButton("Dark Mode");
        darkModeToggle.setFont(new Font("Segoe UI", Font.BOLD, 13));
        darkModeToggle.setFocusPainted(false);
        darkModeToggle.setBackground(new Color(230, 230, 230));
        darkModeToggle.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(200, 200, 200)),
            BorderFactory.createEmptyBorder(5, 15, 5, 15)
        ));

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
        JPanel controlsPanel = new JPanel(new GridBagLayout());
        controlsPanel.setBackground(new Color(245, 245, 245));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Row 0: All controls in a single row
        gbc.gridx = 0; gbc.gridy = 0;
        controlsPanel.add(new JLabel("Network Interface:"), gbc);
        gbc.gridx = 1;
        controlsPanel.add(interfaceComboBox, gbc);

        gbc.gridx = 2;
        controlsPanel.add(new JLabel("Protocol:"), gbc);
        gbc.gridx = 3;
        controlsPanel.add(protocolComboBox, gbc);

        gbc.gridx = 4;
        controlsPanel.add(buttonStart, gbc);
        gbc.gridx = 5;
        controlsPanel.add(buttonStop, gbc);
        gbc.gridx = 6;
        controlsPanel.add(buttonExit, gbc);
        gbc.gridx = 7;
        controlsPanel.add(rlEnabledCheckbox, gbc);
        gbc.gridx = 8;
        controlsPanel.add(darkModeToggle, gbc);
        gbc.gridx = 9;
        gbc.weightx = 1.0;
        controlsPanel.add(Box.createHorizontalGlue(), gbc); // push status label to the right
        gbc.gridx = 10;
        gbc.weightx = 0;
        controlsPanel.add(statusLabel, gbc);

        setLayout(new BorderLayout());
        add(controlsPanel, BorderLayout.CENTER);
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
    public JToggleButton getDarkModeToggle() { return darkModeToggle; }

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