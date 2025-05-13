package com.example.gui.components;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;

public class SimulationPanel extends JPanel {
    private JButton simulateDdosButton;
    private JButton simulateSqlInjectionButton;
    private JButton simulatePortScanButton;
    private JButton testSnortRulesButton;

    public SimulationPanel() {
        setLayout(new BoxLayout(this, BoxLayout.X_AXIS));
        setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("Attack Simulations"),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));
        setBackground(new Color(245, 245, 245));
        initializeComponents();
        setupLayout();
    }

    private void initializeComponents() {
        simulateDdosButton = createButton("Simulate XSS Attack", "xss.png");
        simulateSqlInjectionButton = createButton("Simulate SQL Injection", "sql.png");
        simulatePortScanButton = createButton("Simulate Port Scan", "scan.png");
        testSnortRulesButton = createButton("Test Snort Rules", "snort.png");

        // Disable buttons initially
        simulateDdosButton.setEnabled(false);
        simulateSqlInjectionButton.setEnabled(false);
        simulatePortScanButton.setEnabled(false);
        testSnortRulesButton.setEnabled(false);
    }

    private JButton createButton(String text, String iconName) {
        JButton button = new JButton(text);
        try {
            ImageIcon icon = new ImageIcon(getClass().getResource("/icons/" + iconName));
            Image scaledImage = icon.getImage().getScaledInstance(24, 24, Image.SCALE_SMOOTH);
            button.setIcon(new ImageIcon(scaledImage));
        } catch (Exception e) {
            // Icon not found, continue without it
        }
        button.setFocusPainted(false);
        button.setBackground(new Color(240, 240, 240));
        button.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(200, 200, 200)),
            BorderFactory.createEmptyBorder(10, 15, 10, 15)
        ));
        button.setFont(new Font("Arial", Font.BOLD, 12));
        return button;
    }

    private void setupLayout() {
        add(Box.createHorizontalStrut(10));
        add(simulateDdosButton);
        add(Box.createHorizontalStrut(10));
        add(simulateSqlInjectionButton);
        add(Box.createHorizontalStrut(10));
        add(simulatePortScanButton);
        add(Box.createHorizontalStrut(10));
        add(testSnortRulesButton);
        add(Box.createHorizontalGlue());
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