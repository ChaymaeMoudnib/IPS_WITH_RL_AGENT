package com.example;

import com.example.gui.Gui;
import com.example.util.RuleLoader;
import com.example.util.Rule;
import com.example.detection.RuleEngine;
import javax.swing.SwingUtilities;
import java.awt.Color;
import java.awt.Font;
import javax.swing.BorderFactory;
import javax.swing.UIManager;
import java.util.List;

public class Main {
    private static RuleLoader ruleLoader;
    private static RuleEngine ruleEngine;

    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            UIManager.put("Panel.background", new Color(236, 245, 251));
            UIManager.put("Button.background", new Color(174, 214, 241));
            UIManager.put("Button.foreground", new Color(33, 97, 140));
            UIManager.put("Button.font", new Font("Segoe UI", Font.BOLD, 13));
            UIManager.put("Label.foreground", new Color(33, 97, 140));
            UIManager.put("Label.font", new Font("Segoe UI", Font.PLAIN, 14));
            UIManager.put("TitledBorder.border", BorderFactory.createLineBorder(new Color(52, 152, 219), 2));
            UIManager.put("TitledBorder.titleColor", new Color(33, 97, 140));
            UIManager.put("TitledBorder.font", new Font("Segoe UI", Font.BOLD, 16));
            UIManager.put("TextArea.background", Color.WHITE);
            UIManager.put("TextArea.foreground", new Color(30, 30, 30));
            UIManager.put("TextArea.font", new Font("Segoe UI", Font.PLAIN, 14));
            UIManager.put("ScrollPane.border", BorderFactory.createLineBorder(new Color(52, 152, 219), 1));
            UIManager.put("ComboBox.background", new Color(174, 214, 241));
            UIManager.put("ComboBox.foreground", new Color(33, 97, 140));
            UIManager.put("ComboBox.font", new Font("Segoe UI", Font.PLAIN, 14));
            UIManager.put("CheckBox.background", new Color(236, 245, 251));
            UIManager.put("CheckBox.foreground", new Color(33, 97, 140));
            UIManager.put("CheckBox.font", new Font("Segoe UI", Font.PLAIN, 14));
        } catch (Exception e) {
            // fallback
        }
        // Initialize rule loader and rule engine
        ruleLoader = new RuleLoader();
        ruleEngine = new RuleEngine();
        List<Rule> rules = ruleLoader.getRules();
        ruleEngine.setRules(rules);
        
        SwingUtilities.invokeLater(() -> {
            try {
                Gui gui = new Gui();
                gui.setRuleEngine(ruleEngine); // Pass rule engine to GUI
                gui.setVisible(true);
            } catch (Exception e) {
                System.err.println("Error starting application: " + e.getMessage());
                e.printStackTrace();
            }
        });
    }

    public static void reloadRules() {
        ruleLoader.reloadRules();
        List<Rule> rules = ruleLoader.getRules();
        ruleEngine.setRules(rules);
    }
}