package com.example.util;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class RuleLoader {
    private final SnortRuleParser snortParser;
    private List<Rule> rules;

    public RuleLoader() {
        this.snortParser = new SnortRuleParser();
        this.rules = new ArrayList<>();
        loadRules();
    }

    private void loadRules() {
        try {
            rules = snortParser.parseRules();
        } catch (IOException e) {
            System.err.println("Error loading rules: " + e.getMessage());
        }
    }

    public List<Rule> getRules() {
        return rules;
    }

    public void reloadRules() {
        try {
            rules = snortParser.parseRules();
        } catch (IOException e) {
            System.err.println("Error reloading rules: " + e.getMessage());
        }
    }
} 