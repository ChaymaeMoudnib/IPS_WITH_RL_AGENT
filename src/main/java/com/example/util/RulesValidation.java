package com.example.util;

import java.util.regex.Pattern;
import java.util.Map;
import java.util.HashMap;

// Protocol Source:IP_Address Source:Port  Destination:IP_Address Destination:Port  Message
//  0          1                   2              3                       4            5
//  TCP         any                 80         10.199.12.8	           any           any
public class RulesValidation {
    // Constantes pour les protocoles supportés
    public static final String PROTOCOL_TCP = "TCP";
    public static final String PROTOCOL_UDP = "UDP";
    public static final String PROTOCOL_ICMP = "ICMP";
    public static final String PROTOCOL_HTTP = "HTTP";
    public static final String PROTOCOL_ANY = "any";
    
    // Constantes pour les directions
    public static final String DIRECTION_BIDIRECTIONAL = "<>";
    public static final String DIRECTION_FORWARD = "->";
    public static final String DIRECTION_REVERSE = "<-";
    
    // Options Snort courantes
    public static final String OPTION_MSG = "msg";
    public static final String OPTION_SID = "sid";
    public static final String OPTION_CONTENT = "content";
    public static final String OPTION_REV = "rev";
    public static final String OPTION_CLASSTYPE = "classtype";
    
    /**
     * Valide une règle complète avec options
     * @param rule La règle à valider
     * @return true si la règle est valide, false sinon
     */
    public static boolean validateRule(Rule rule) {
        if (rule == null) return false;
        
        return validateProtocol(rule.getProtocol()) &&
               validateIp(rule.getSourceIp()) &&
               validatePort(rule.getSourcePort()) &&
               validateDirection(rule.getDirection()) &&
               validateIp(rule.getDestinationIp()) &&
               validatePort(rule.getDestinationPort()) &&
               validateOptions(rule.getOptions());
    }
    
    /**
     * Valide un tableau de tokens représentant une règle
     * @param tokens Les tokens de la règle
     * @return true si la règle est valide, false sinon
     */
    public static boolean rulesValidation(String[] tokens) {
        if (tokens == null || tokens.length < 6) return false;
        
        try {
            return validateProtocol(tokens[0]) &&
                   validateIp(tokens[1]) &&
                   validatePort(tokens[2]) &&
                   validateDirection(tokens[3]) &&
                   validateIp(tokens[4]) &&
                   validatePort(tokens[5]);
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Valide une adresse IP
     */
    private static boolean validateIp(String input) {
        if (input == null) return false;
        if (input.equalsIgnoreCase(PROTOCOL_ANY)) return true;
        
        Pattern p = Pattern.compile("^((0|1\\d?\\d?|2[0-4]?\\d?|25[0-5]?|[3-9]\\d?)\\.){3}(0|1\\d?\\d?|2[0-4]?\\d?|25[0-5]?|[3-9]\\d?)$");
        return p.matcher(input).matches();
    }
    
    /**
     * Valide un port
     */
    private static boolean validatePort(String input) {
        if (input == null) return false;
        if (input.equalsIgnoreCase(PROTOCOL_ANY)) return true;
        
        try {
            int port = Integer.parseInt(input);
            return port >= 0 && port < 65536;
        } catch (NumberFormatException e) {
            return false;
        }
    }
    
    /**
     * Valide un protocole
     */
    private static boolean validateProtocol(String input) {
        if (input == null) return false;
        if (input.equalsIgnoreCase(PROTOCOL_ANY)) return true;
        
        return input.equals(PROTOCOL_TCP) ||
               input.equals(PROTOCOL_UDP) ||
               input.equals(PROTOCOL_ICMP) ||
               input.equals(PROTOCOL_HTTP);
    }
    
    /**
     * Valide une direction de flux
     */
    private static boolean validateDirection(String input) {
        if (input == null) return false;
        
        return input.equals(DIRECTION_BIDIRECTIONAL) ||
               input.equals(DIRECTION_FORWARD) ||
               input.equals(DIRECTION_REVERSE);
    }
    
    /**
     * Valide les options Snort
     */
    private static boolean validateOptions(Map<String, String> options) {
        if (options == null) return true; // Les options sont optionnelles
        
        for (Map.Entry<String, String> option : options.entrySet()) {
            String key = option.getKey();
            String value = option.getValue();
            
            // Validation spécifique selon le type d'option
            switch (key) {
                case OPTION_SID:
                    try {
                        Integer.parseInt(value);
                    } catch (NumberFormatException e) {
                        return false;
                    }
                    break;
                    
                case OPTION_REV:
                    try {
                        Integer.parseInt(value);
                    } catch (NumberFormatException e) {
                        return false;
                    }
                    break;
                    
                case OPTION_CONTENT:
                    if (value == null || value.isEmpty()) return false;
                    break;
                    
                case OPTION_MSG:
                    if (value == null || value.isEmpty()) return false;
                    break;
                    
                case OPTION_CLASSTYPE:
                    if (value == null || value.isEmpty()) return false;
                    break;
            }
        }
        
        return true;
    }
    
    /**
     * Parse une chaîne de règle en objet Rule
     */
    public static Rule parseRule(String ruleString) {
        if (ruleString == null || ruleString.trim().isEmpty()) {
            return null;
        }
        
        try {
            String[] parts = ruleString.split("\\s+");
            if (parts.length < 6) return null;
            
            Rule rule = new Rule();
            rule.setProtocol(parts[0]);
            rule.setSourceIp(parts[1]);
            rule.setSourcePort(parts[2]);
            rule.setDirection(parts[3]);
            rule.setDestinationIp(parts[4]);
            rule.setDestinationPort(parts[5]);
            
            // Parse les options si présentes
            if (parts.length > 6) {
                for (int i = 6; i < parts.length; i++) {
                    String[] option = parts[i].split(":");
                    if (option.length == 2) {
                        rule.addOption(option[0], option[1]);
                    }
                }
            }
            
            return rule;
        } catch (Exception e) {
            return null;
        }
    }
}
