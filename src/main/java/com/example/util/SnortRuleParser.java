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

public class SnortRuleParser {
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
        ".*?\\)"
    );

    public List<Rule> parseRules() throws IOException {
        List<Rule> rules = new ArrayList<>();
        int ruleCount = 0;
        
        try (BufferedReader reader = new BufferedReader(new FileReader(RULES_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.trim().isEmpty() || line.startsWith("#")) {
                    continue;
                }
                
                Matcher matcher = RULE_PATTERN.matcher(line);
                if (matcher.find()) {
                    Rule rule = new Rule();
                    
                    // Basic rule properties
                    rule.setProtocol(matcher.group(1));
                    rule.setSourceIp(matcher.group(2));
                    rule.setSourcePort(matcher.group(3));
                    rule.setDestinationIp(matcher.group(4));
                    rule.setDestinationPort(matcher.group(5));
                    
                    // Message and metadata
                    Map<String, String> options = new HashMap<>();
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
                        options.put("classtype", matcher.group(10));
                    }
                    
                    // SID and revision
                    if (matcher.group(11) != null) {
                        rule.setId("snort_" + matcher.group(11));
                        options.put("sid", matcher.group(11));
                    }
                    if (matcher.group(12) != null) {
                        options.put("rev", matcher.group(12));
                    }
                    
                    rule.setOptions(options);
                    rules.add(rule);
                    ruleCount++;
                }
            }
        }
        
        System.out.println("Loaded " + ruleCount + " Snort rules");
        return rules;
    }
} 