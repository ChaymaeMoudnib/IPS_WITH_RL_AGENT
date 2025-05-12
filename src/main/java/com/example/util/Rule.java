package com.example.util;

import java.util.HashMap;
import java.util.Map;

public class Rule {
    private String id;
    private String name;
    private String protocol;
    private String sourceIp;
    private String sourcePort;
    private String destinationIp;
    private String destinationPort;
    private String direction;
    private Map<String, String> options;
    
    public Rule() {
        this.options = new HashMap<>();
    }
    
    public boolean matches(Map<String, String> packetData) {
        if (packetData == null) {
            return false;
        }

        // Vérifier le protocole
        String protocol = packetData.get("protocol");
        if (protocol == null || (!this.protocol.equals("any") && !this.protocol.equalsIgnoreCase(protocol))) {
            return false;
        }

        // Vérifier l'IP source
        String srcIp = packetData.get("srcIP");
        if (srcIp != null && !this.sourceIp.equals("any") && !this.sourceIp.equals(srcIp)) {
            return false;
        }

        // Vérifier le port source
        String srcPort = packetData.get("srcPort");
        if (srcPort != null && !this.sourcePort.equals("any") && !this.sourcePort.equals(srcPort)) {
            return false;
        }

        // Vérifier l'IP destination
        String dstIp = packetData.get("destIP");
        if (dstIp != null && !this.destinationIp.equals("any") && !this.destinationIp.equals(dstIp)) {
            return false;
        }

        // Vérifier le port destination
        String dstPort = packetData.get("destPort");
        if (dstPort != null && !this.destinationPort.equals("any") && !this.destinationPort.equals(dstPort)) {
            return false;
        }

        // Vérifier le contenu si spécifié
        String content = this.options.get("content");
        if (content != null) {
            String data = packetData.get("data");
            String payload = packetData.get("payload");
            boolean nocase = "true".equalsIgnoreCase(this.options.get("nocase"));
            
            if (data == null && payload == null) {
                return false;
            }
            
            boolean dataMatches = false;
            if (data != null) {
                dataMatches = nocase ? 
                    data.toLowerCase().contains(content.toLowerCase()) :
                    data.contains(content);
            }
            
            boolean payloadMatches = false;
            if (payload != null) {
                payloadMatches = nocase ?
                    payload.toLowerCase().contains(content.toLowerCase()) :
                    payload.contains(content);
            }
            
            if (!dataMatches && !payloadMatches) {
                return false;
            }
        }

        return true;
    }

    private boolean containsAllFlags(String packetFlags, String ruleFlags) {
        for (char flag : ruleFlags.toCharArray()) {
            if (!packetFlags.contains(String.valueOf(flag))) {
                return false;
            }
        }
        return true;
    }

    // Getters and Setters
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public String getSourcePort() {
        return sourcePort;
    }

    public void setSourcePort(String sourcePort) {
        this.sourcePort = sourcePort;
    }

    public String getDestinationIp() {
        return destinationIp;
    }

    public void setDestinationIp(String destinationIp) {
        this.destinationIp = destinationIp;
    }

    public String getDestinationPort() {
        return destinationPort;
    }

    public void setDestinationPort(String destinationPort) {
        this.destinationPort = destinationPort;
    }

    public String getDirection() {
        return direction;
    }

    public void setDirection(String direction) {
        this.direction = direction;
    }

    public Map<String, String> getOptions() {
        return options;
    }

    public void setOptions(Map<String, String> options) {
        this.options = options;
    }
    
    public void addOption(String key, String value) {
        this.options.put(key, value);
    }
    
    public String getOption(String key) {
        return this.options.get(key);
    }
    
    @Override
    public String toString() {
        return String.format("Rule{id='%s', name='%s', protocol='%s', sourceIp='%s', sourcePort='%s', destinationIp='%s', destinationPort='%s', options=%s}",
                id, name, protocol, sourceIp, sourcePort, destinationIp, destinationPort, options);
    }
} 