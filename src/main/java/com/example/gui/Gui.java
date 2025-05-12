package com.example.gui;

import com.example.gui.components.*;
import com.example.util.PacketReader;
import com.example.util.PacketReaderFactory;
import com.example.detection.RuleEngine;
import com.example.detection.Alert;
import com.example.rl.RLAgent;
import com.example.rl.Environment;
import com.example.rl.State;
import com.example.rl.Action;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class Gui extends JFrame {
    private ControlPanel controlPanel;
    private SimulationPanel simulationPanel;
    private PacketDisplayPanel packetDisplayPanel;
    private StatisticsPanel statisticsPanel;
    private LogPanel logPanel;
    private RLDecisionsPanel rlDecisionsPanel;

    private PacketReader reader;
    private RuleEngine ruleEngine;
    private RLAgent rlAgent;
    private Environment env;
    private AtomicBoolean isCapturing = new AtomicBoolean(false);
    private AtomicInteger allowedCount = new AtomicInteger(0);
    private AtomicInteger blockedCount = new AtomicInteger(0);

    public Gui() {
        setTitle("Network Intrusion Detection System");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1200, 800);
        setLocationRelativeTo(null);

        initializeComponents();
        setupLayout();
        setupEventListeners();
        initializeSystems();
    }

    private void initializeComponents() {
        controlPanel = new ControlPanel();
        simulationPanel = new SimulationPanel();
        packetDisplayPanel = new PacketDisplayPanel();
        statisticsPanel = new StatisticsPanel();
        logPanel = new LogPanel();
        rlDecisionsPanel = new RLDecisionsPanel();
    }

    private void setupLayout() {
        setLayout(new BorderLayout());

        // Top panel with controls and simulation
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(controlPanel, BorderLayout.CENTER);
        topPanel.add(simulationPanel, BorderLayout.SOUTH);

        // Middle panel with packet display and statistics
        JPanel middlePanel = new JPanel(new GridLayout(1, 2));
        middlePanel.add(packetDisplayPanel);
        middlePanel.add(statisticsPanel);

        // Bottom panel with logs and RL decisions
        JPanel bottomPanel = new JPanel(new GridLayout(1, 2));
        bottomPanel.add(logPanel);
        bottomPanel.add(rlDecisionsPanel);

        // Add all panels to the frame
        add(topPanel, BorderLayout.NORTH);
        add(middlePanel, BorderLayout.CENTER);
        add(bottomPanel, BorderLayout.SOUTH);
    }

    private void setupEventListeners() {
        // Control Panel events
        controlPanel.getButtonStart().addActionListener(e -> startCapture());
        controlPanel.getButtonStop().addActionListener(e -> stopCapture());
        controlPanel.getButtonExit().addActionListener(e -> System.exit(0));
        controlPanel.getProtocolComboBox().addActionListener(e -> {
            String selectedProtocol = (String) controlPanel.getProtocolComboBox().getSelectedItem();
            controlPanel.setSelectedProtocol(selectedProtocol);
        });

        // Simulation Panel events
        simulationPanel.getSimulateDdosButton().addActionListener(e -> simulateXssAttack());
        simulationPanel.getSimulateSqlInjectionButton().addActionListener(e -> simulateSqlInjection());
        simulationPanel.getSimulatePortScanButton().addActionListener(e -> simulatePortScan());
        simulationPanel.getTestSnortRulesButton().addActionListener(e -> testSnortRules());
    }

    private void initializeSystems() {
        ruleEngine = new RuleEngine();
        rlAgent = new RLAgent();
        env = new Environment();

        try {
            rlAgent.loadModel("trained_model.rl");
            logPanel.appendText("RL model loaded successfully\n");
        } catch (Exception e) {
            logPanel.appendText("Error loading RL model: " + e.getMessage() + "\n");
        }
    }

    private void startCapture() {
        if (isCapturing.get()) return;

        String selectedInterface = controlPanel.getSelectedInterface();
        if (selectedInterface == null) {
            JOptionPane.showMessageDialog(this, "Please select a network interface");
            return;
        }

        try {
            reader = PacketReaderFactory.createPacketReader("live", selectedInterface);
            isCapturing.set(true);
            controlPanel.getButtonStart().setEnabled(false);
            controlPanel.getButtonStop().setEnabled(true);
            simulationPanel.setSimulationEnabled(true);
            controlPanel.setStatus("Capturing...");

            new Thread(this::captureLoop).start();
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error starting capture: " + e.getMessage());
            stopCapture();
        }

    }

    private void stopCapture() {
        isCapturing.set(false);
        if (reader != null) {
            reader.close();
        }
        controlPanel.getButtonStart().setEnabled(true);
        controlPanel.getButtonStop().setEnabled(false);
        simulationPanel.setSimulationEnabled(false);
        controlPanel.setStatus("Stopped");
    }

    private void captureLoop() {
        while (isCapturing.get()) {
            try {
                Packet packet = reader.getNextPacket();
                if (packet != null) {
                    processPacket(packet);
                }
            } catch (Exception e) {
                logPanel.appendText("Error processing packet: " + e.getMessage() + "\n");
            }
        }
    }

    private void processPacket(Packet packet) {
        State state = env.extractState(packet);
        Map<String, String> packetData = new HashMap<>();
        packetData.put("protocol", state.getProtocol());
        packetData.put("srcPort", state.getSrcPort());
        packetData.put("srcIP", state.getSrcIP());
        packetData.put("destPort", state.getDestPort());
        packetData.put("destIP", state.getDestIP());

        // Update packet display
        packetDisplayPanel.appendPacket(packetData);

        // Update statistics
        statisticsPanel.updateStatistics(packetData);

        // Check rules
        boolean ruleMatch = ruleEngine.matches(packetData);
        if (ruleMatch) {
            Alert alert = ruleEngine.getLastAlert();
            logPanel.displayAlert(alert);
            statisticsPanel.incrementAlertCount();
        }

        // RL decision if enabled
        if (controlPanel.getRlEnabledCheckbox().isSelected()) {
            Action rlAction = rlAgent.getAction(state);
            boolean isAllowed = rlAction.isAllowed();

            if (isAllowed) {
                allowedCount.incrementAndGet();
            } else {
                blockedCount.incrementAndGet();
            }

            String decision = String.format("[%s] %s:%s -> %s:%s (%s) - %s",
                    state.getProtocol(),
                    state.getSrcIP(),
                    state.getSrcPort(),
                    state.getDestIP(),
                    state.getDestPort(),
                    state.getData(),
                    isAllowed ? "ALLOWED" : "BLOCKED");

            rlDecisionsPanel.appendDecision(decision);

            // Update RL statistics
            Map<String, Object> rlStats = new HashMap<>();
            rlStats.put("allowedCount", allowedCount.get());
            rlStats.put("blockedCount", blockedCount.get());
            rlStats.put("accuracy", calculateAccuracy());
            statisticsPanel.updateRLStats(rlStats);
        }
    }

    private double calculateAccuracy() {
        int total = allowedCount.get() + blockedCount.get();
        return total > 0 ? (double) allowedCount.get() / total * 100 : 0;
    }

    private void simulateXssAttack() {
        // Implementation for XSS attack simulation
        logPanel.appendText("Simulating XSS attack...\n");
    }

    private void simulateSqlInjection() {
        // Implementation for SQL injection simulation
        logPanel.appendText("Simulating SQL injection attack...\n");
    }

    private void simulatePortScan() {
        // Implementation for port scan simulation
        logPanel.appendText("Simulating port scan attack...\n");
    }

    private void testSnortRules() {
        // Implementation for Snort rules testing
        logPanel.appendText("Testing Snort rules...\n");
    }

    public void setRuleEngine(RuleEngine ruleEngine) {
        this.ruleEngine = ruleEngine;
    }

    public PacketDisplayPanel getPacketDisplayPanel() {
        return packetDisplayPanel;
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            Gui gui = new Gui();
            gui.setVisible(true);
        });
    }
}


