package com.example;

import com.example.gui.Gui;
import com.example.util.RuleLoader;
import com.example.util.Rule;
import com.example.detection.RuleEngine;
import javax.swing.SwingUtilities;
import java.util.List;

public class Main {
    private static RuleLoader ruleLoader;
    private static RuleEngine ruleEngine;

    public static void main(String[] args) {
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