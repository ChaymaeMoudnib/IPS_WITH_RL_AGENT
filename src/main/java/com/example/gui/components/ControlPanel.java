package com.example.gui.components;

import javax.swing.*;
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
        setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        initializeComponents();
        setupLayout();
        loadNetworkInterfaces();
    }

    private void initializeComponents() {
        interfaceComboBox = new JComboBox<>();
        protocolComboBox = new JComboBox<>(new String[] { "ALL", "TCP", "UDP", "HTTP", "HTTPS" });
        buttonStart = new JButton("Start Capture");
        buttonStop = new JButton("Stop Capture");
        buttonExit = new JButton("Exit");
        rlEnabledCheckbox = new JCheckBox("Enable RL IP Control");
        statusLabel = new JLabel("Status: Ready");

        buttonStop.setEnabled(false);
        rlEnabledCheckbox.setSelected(false);
    }

    private void setupLayout() {
        JPanel controlsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controlsPanel.add(new JLabel("Network Interface:"));
        controlsPanel.add(interfaceComboBox);
        controlsPanel.add(new JLabel("Protocol:"));
        controlsPanel.add(protocolComboBox);
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
    public void setStatus(String status) { statusLabel.setText("Status: " + status); }
} 