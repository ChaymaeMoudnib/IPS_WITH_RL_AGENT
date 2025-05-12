package com.example.util;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.logging.Level;

public class RuleLoader {
    private static final Logger LOGGER = Logger.getLogger(RuleLoader.class.getName());
    private final SnortRuleParser snortParser;
    private List<Rule> rules;
    private boolean debugMode = false;

    public RuleLoader() {
        this.snortParser = new SnortRuleParser();
        this.rules = new ArrayList<>();
        loadRules();
    }

    private void loadRules() {
        try {
            rules = snortParser.parseRules();
            if (debugMode) {
                LOGGER.info("Loaded " + rules.size() + " rules");
            }
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Error loading rules", e);
        }
    }

    public List<Rule> getRules() {
        return new ArrayList<>(rules);
    }

    public void reloadRules() {
        try {
            rules = snortParser.parseRules();
            if (debugMode) {
                LOGGER.info("Reloaded " + rules.size() + " rules");
            }
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Error reloading rules", e);
        }
    }

    public void setDebugMode(boolean enabled) {
        this.debugMode = enabled;
    }
} 