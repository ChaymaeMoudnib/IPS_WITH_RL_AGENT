package com.example;

import com.example.gui.Gui;
import com.example.util.RuleLoader;
import com.example.util.Rule;
import javax.swing.SwingUtilities;
import java.util.List;

public class Main {
    private static RuleLoader ruleLoader;

    public static void main(String[] args) {
        // Initialize rule loader
        ruleLoader = new RuleLoader();
        List<Rule> rules = ruleLoader.getRules();
        
    
        SwingUtilities.invokeLater(() -> {
            try {
                Gui gui = new Gui();
                gui.setRules(rules); // Pass rules to GUI
                gui.setVisible(true);
            } catch (Exception e) {
                System.err.println("Error starting application: " + e.getMessage());
                e.printStackTrace();
            }
        });
    }

    public static void reloadRules() {
        ruleLoader.reloadRules();
    }
}