package com.example.gui.components;

import javax.swing.*;
import java.awt.*;

public class SimulationPanel extends JPanel {
    private JButton simulateDdosButton;
    private JButton simulateSqlInjectionButton;
    private JButton simulatePortScanButton;
    private JButton testSnortRulesButton;

    public SimulationPanel() {
        setLayout(new GridLayout(2, 2, 5, 5));
        setBorder(BorderFactory.createTitledBorder("Attack Simulations"));
        initializeComponents();
        setupLayout();
    }

    private void initializeComponents() {
        simulateDdosButton = new JButton("Simulate XSS Attack");
        simulateSqlInjectionButton = new JButton("Simulate SQL Injection");
        simulatePortScanButton = new JButton("Simulate Port Scan");
        testSnortRulesButton = new JButton("Test Snort Rules");

        // Disable buttons initially
        simulateDdosButton.setEnabled(false);
        simulateSqlInjectionButton.setEnabled(false);
        simulatePortScanButton.setEnabled(false);
        testSnortRulesButton.setEnabled(false);
    }

    private void setupLayout() {
        add(simulateDdosButton);
        add(simulateSqlInjectionButton);
        add(simulatePortScanButton);
        add(testSnortRulesButton);
    }

    // Getters for buttons
    public JButton getSimulateDdosButton() { return simulateDdosButton; }
    public JButton getSimulateSqlInjectionButton() { return simulateSqlInjectionButton; }
    public JButton getSimulatePortScanButton() { return simulatePortScanButton; }
    public JButton getTestSnortRulesButton() { return testSnortRulesButton; }

    // Enable/disable all simulation buttons
    public void setSimulationEnabled(boolean enabled) {
        simulateDdosButton.setEnabled(enabled);
        simulateSqlInjectionButton.setEnabled(enabled);
        simulatePortScanButton.setEnabled(enabled);
        testSnortRulesButton.setEnabled(enabled);
    }
} 