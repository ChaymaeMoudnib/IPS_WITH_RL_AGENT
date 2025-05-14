package com.example.util;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.logging.Logger;
import java.util.logging.Level;

public class SnortRuleParser {
    private static final Logger LOGGER = Logger.getLogger(SnortRuleParser.class.getName());
    private static final String RULES_FILE = "src/main/resources/rules/snort.rules";
    private static final Pattern RULE_PATTERN = Pattern.compile(
        "alert\\s+(\\w+)\\s+([^\\s]+)\\s+([^\\s]+)\\s+->\\s+([^\\s]+)\\s+([^\\s]+)\\s+\\(\\s*" +
        "(?:msg:\"([^\"]+)\";\\s*)?" +
        "(?:flow:([^;]+);\\s*)?" +
        "(?:content:\"([^\"]+)\"(?:,\\s*(?:depth|offset|nocase|fast_pattern)\\s*(?:\\d+)?)?;\\s*)?" +
        "(?:metadata:([^;]+);\\s*)?" +
        "(?:classtype:([^;]+);\\s*)?" +
        "(?:sid:(\\d+);\\s*)?" +
        "(?:rev:(\\d+);\\s*)?" +
        "(?:icmp_id:(\\d+);\\s*)?" +
        "(?:itype:(\\d+);\\s*)?" +
        "(?:icode:(\\d+);\\s*)?" +
        ".*?\\)"
    );

    public List<Rule> parseRules() throws IOException {
        List<Rule> rules = new ArrayList<>();
        int ruleCount = 0;
        int lineCount = 0;

        try (BufferedReader reader = new BufferedReader(new FileReader(RULES_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                lineCount++;
                if (line.trim().isEmpty() || line.startsWith("#")) {
                    continue;
                }

                try {
                    Rule rule = parseRule(line);
                    if (rule != null) {
                        rules.add(rule);
                        ruleCount++;
                    }
                } catch (Exception e) {
                    LOGGER.log(Level.WARNING, "Error parsing rule at line " + lineCount, e);
                }
            }
        }

        LOGGER.info("Loaded " + ruleCount + " rules");
        return rules;
    }

    private Rule parseRule(String line) {
        Matcher matcher = RULE_PATTERN.matcher(line);
        if (!matcher.find()) {
            return null;
        }

        try {
            Rule rule = new Rule();
            
            // Basic rule properties
            rule.setProtocol(matcher.group(1).toUpperCase());
            rule.setSourceIp(matcher.group(2));
            rule.setSourcePort(matcher.group(3));
            rule.setDestinationIp(matcher.group(4));
            rule.setDestinationPort(matcher.group(5));
            
            // Options
            Map<String, String> options = new HashMap<>();
            
            // Message
            if (matcher.group(6) != null) {
                options.put("msg", matcher.group(6));
            }
            
            // Flow
            if (matcher.group(7) != null) {
                options.put("flow", matcher.group(7));
            }
            
            // Content
            if (matcher.group(8) != null) {
                options.put("content", matcher.group(8));
            }
            
            // Metadata
            if (matcher.group(9) != null) {
                options.put("metadata", matcher.group(9));
            }
            
            // Classification
            if (matcher.group(10) != null) {
                String classtype = matcher.group(10);
                options.put("classtype", classtype);
                options.put("severity", getSeverityFromClasstype(classtype));
            }
            
            // SID and revision
            if (matcher.group(11) != null) {
                rule.setId("snort_" + matcher.group(11));
                options.put("sid", matcher.group(11));
            }
            if (matcher.group(12) != null) {
                options.put("rev", matcher.group(12));
            }

            // ICMP specific options
            if (matcher.group(13) != null) {
                options.put("icmp_id", matcher.group(13));
            }
            if (matcher.group(14) != null) {
                options.put("itype", matcher.group(14));
            }
            if (matcher.group(15) != null) {
                options.put("icode", matcher.group(15));
            }
            
            // Default severity if not set
            if (!options.containsKey("severity")) {
                options.put("severity", "MEDIUM");
            }
            
            rule.setOptions(options);
            return rule;
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error creating rule from match", e);
            return null;
        }
    }

    private String getSeverityFromClasstype(String classtype) {
        if (classtype == null) return "MEDIUM";
        
        switch (classtype.toLowerCase()) {
            case "attempted-admin":
            case "attempted-user":
            case "successful-admin":
            case "successful-user":
            case "trojan-activity":
            case "web-application-attack":
                return "HIGH";
            case "attempted-dos":
            case "attempted-recon":
            case "policy-violation":
            case "suspicious-login":
                return "MEDIUM";
            case "not-suspicious":
            case "protocol-command-decode":
            case "misc-activity":
                return "LOW";
            default:
                return "MEDIUM";
        }
    }
} 