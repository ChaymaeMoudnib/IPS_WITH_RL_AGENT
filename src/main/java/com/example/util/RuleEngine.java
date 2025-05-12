package com.example.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.HashMap;
import java.io.IOException;
import java.util.Set;
import java.util.logging.Logger;
import java.util.logging.Level;

public class RuleEngine {
    private static final Logger LOGGER = Logger.getLogger(RuleEngine.class.getName());
    private List<Rule> rules;
    private Rule lastMatchedRule;
    private Map<String, Integer> thresholdCounts;
    private Map<String, Long> thresholdTimestamps;
    private boolean debugMode = false;

    private static final Pattern RULE_PATTERN = Pattern.compile(
            "^(TCP|UDP|ICMP)\\s+" +
                    "([\\w\\.\\*]+)\\s+" +
                    "([\\w\\.\\*]+)\\s+" +
                    "->\\s+" +
                    "([\\w\\.\\*]+)\\s+" +
                    "([\\w\\.\\*]+)\\s*" +
                    "\\((.*)\\)$");

    public RuleEngine() {
        this.rules = new ArrayList<>();
        this.thresholdCounts = new HashMap<>();
        this.thresholdTimestamps = new HashMap<>();
    }

    /**
     * Ajoute une règle au moteur
     */
    public void addRule(Rule rule) {
        if (rule != null && RulesValidation.validateRule(rule)) {
            rules.add(rule);
            if (debugMode) {
                LOGGER.fine("Added rule: " + rule.getId());
            }
        }
    }

    /**
     * Ajoute une règle à partir d'une chaîne
     */
    public void addRule(String ruleString) {
        try {
            Rule rule = parseRule(ruleString);
            if (rule != null) {
                rules.add(rule);
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid rule format: " + ruleString);
        }
    }

    private Rule parseRule(String ruleString) {
        Matcher matcher = RULE_PATTERN.matcher(ruleString);
        if (!matcher.matches()) {
            return null;
        }

        Rule rule = new Rule();
        rule.setProtocol(matcher.group(1));
        rule.setSourceIp(matcher.group(2));
        rule.setSourcePort(matcher.group(3));
        rule.setDestinationIp(matcher.group(4));
        rule.setDestinationPort(matcher.group(5));

        // Parse options
        String options = matcher.group(6);
        String[] optionPairs = options.split(";");
        for (String pair : optionPairs) {
            String[] keyValue = pair.trim().split(":");
            if (keyValue.length == 2) {
                rule.addOption(keyValue[0].trim(), keyValue[1].trim());
            }
        }

        return rule;
    }

    /**
     * Vérifie si un paquet correspond à une règle
     */
    public boolean matchesRule(Map<String, String> packet, Rule rule) {
        if (packet == null || rule == null)
            return false;

        // Vérification du protocole
        if (!rule.getProtocol().equalsIgnoreCase("any") &&
                !rule.getProtocol().equalsIgnoreCase(packet.get("protocol"))) {
            return false;
        }

        // Vérification des adresses IP source
        if (!rule.getSourceIp().equalsIgnoreCase("any") &&
                !rule.getSourceIp().equals(packet.get("srcIp"))) {
            return false;
        }

        // Vérification des ports source
        if (!rule.getSourcePort().equalsIgnoreCase("any") &&
                !rule.getSourcePort().equals(packet.get("srcPort"))) {
            return false;
        }

        // Vérification des adresses IP destination
        if (!rule.getDestinationIp().equalsIgnoreCase("any") &&
                !rule.getDestinationIp().equals(packet.get("dstIp"))) {
            return false;
        }

        // Vérification des ports destination
        if (!rule.getDestinationPort().equalsIgnoreCase("any") &&
                !rule.getDestinationPort().equals(packet.get("dstPort"))) {
            return false;
        }

        // Vérification de la direction
        if (rule.getDirection().equals(RulesValidation.DIRECTION_FORWARD)) {
            // Vérifier que le paquet va dans la bonne direction
            if (!packet.get("srcIp").equals(rule.getSourceIp()) ||
                    !packet.get("dstIp").equals(rule.getDestinationIp())) {
                return false;
            }
        } else if (rule.getDirection().equals(RulesValidation.DIRECTION_REVERSE)) {
            // Vérifier que le paquet va dans la direction inverse
            if (!packet.get("srcIp").equals(rule.getDestinationIp()) ||
                    !packet.get("dstIp").equals(rule.getSourceIp())) {
                return false;
            }
        }

        // Vérification des options
        if (rule.getOptions() != null && !rule.getOptions().isEmpty()) {
            // Vérification du contenu si spécifié
            String content = rule.getOption(RulesValidation.OPTION_CONTENT);
            if (content != null && packet.get("data") != null) {
                if (!packet.get("data").contains(content)) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Vérifie si un paquet correspond à n'importe quelle règle
     */
    public Rule findMatchingRule(Map<String, String> packet) {
        for (Rule rule : rules) {
            if (matchesRule(packet, rule)) {
                return rule;
            }
        }
        return null;
    }

    /**
     * Retourne toutes les règles
     */
    public List<Rule> getRules() {
        return new ArrayList<>(rules);
    }

    /**
     * Efface toutes les règles
     */
    public void clearRules() {
        rules.clear();
        if (debugMode) {
            LOGGER.fine("Rules cleared");
        }
    }

    public boolean matches(Map<String, String> packetData) {
        if (packetData == null) return false;
        
        for (Rule rule : rules) {
            if (rule.matches(packetData)) {
                lastMatchedRule = rule;
                if (debugMode) {
                    LOGGER.fine("Rule matched: " + rule.getId());
                }
                return true;
            }
        }
        return false;
    }

    private boolean containsAllFlags(String packetFlags, String ruleFlags) {
        // Convertir les flags en ensembles de caractères
        Set<Character> packetFlagSet = packetFlags.chars()
                .mapToObj(ch -> (char) ch)
                .collect(java.util.stream.Collectors.toSet());

        Set<Character> ruleFlagSet = ruleFlags.chars()
                .mapToObj(ch -> (char) ch)
                .collect(java.util.stream.Collectors.toSet());

        // Vérifier que tous les flags requis sont présents
        return packetFlagSet.containsAll(ruleFlagSet);
    }

    private boolean checkThreshold(Rule rule) {
        String threshold = rule.getOption("threshold");
        if (threshold == null) {
            return true;
        }

        String[] parts = threshold.split(",");
        int count = 0;
        int seconds = 0;
        String type = "";

        for (String part : parts) {
            String[] keyValue = part.trim().split(" ");
            if (keyValue.length == 2) {
                switch (keyValue[0]) {
                    case "count":
                        count = Integer.parseInt(keyValue[1]);
                        break;
                    case "seconds":
                        seconds = Integer.parseInt(keyValue[1]);
                        break;
                    case "type":
                        type = keyValue[1];
                        break;
                }
            }
        }

        String key = rule.toString() + "_" + type;
        long currentTime = System.currentTimeMillis();

        if (!thresholdTimestamps.containsKey(key) ||
                currentTime - thresholdTimestamps.get(key) > seconds * 1000) {
            thresholdCounts.put(key, 1);
            thresholdTimestamps.put(key, currentTime);
            return false;
        }

        int currentCount = thresholdCounts.getOrDefault(key, 0) + 1;
        thresholdCounts.put(key, currentCount);

        return currentCount >= count;
    }

    public Rule getLastMatchedRule() {
        return lastMatchedRule;
    }

    public int getRuleCount() {
        return rules.size();
    }

    /**
     * Charge les règles depuis un fichier
     * 
     * @param filename Le nom du fichier contenant les règles
     * @return true si le chargement a réussi, false sinon
     */
    public int loadRulesFromFile(String filename) {
        int ruleCount = 0;
        try {
            ruleCount = (int) java.nio.file.Files.lines(java.nio.file.Paths.get(filename))
                    .filter(line -> !line.trim().isEmpty())
                    .peek(this::addRule) // Ajoute chaque règle
                    .count(); // Compte le nombre de règles

        } catch (IOException e) {
            return 0; // En cas d'erreur, retournez 0
        }
        return ruleCount; // Retournez le nombre de règles chargées
    }

    public void setRules(List<Rule> newRules) {
        rules = new ArrayList<>(newRules);
        if (debugMode) {
            LOGGER.fine("Set " + newRules.size() + " rules");
        }
    }

    public void setDebugMode(boolean enabled) {
        this.debugMode = enabled;
    }
}