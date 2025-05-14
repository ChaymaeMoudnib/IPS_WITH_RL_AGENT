package com.example.util;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.logging.Logger;
import java.util.logging.Level;

public class Rule {
    private static final Logger LOGGER = Logger.getLogger(Rule.class.getName());
    private String id;
    private String name;
    private String protocol;
    private String sourceIp;
    private String sourcePort;
    private String destinationIp;
    private String destinationPort;
    private String direction;
    private Map<String, String> options;
    
    // Variables prédéfinies pour les réseaux
    private static final String HOME_NET = "192.168.0.0/16";  // Exemple, à configurer selon le réseau
    private static final String EXTERNAL_NET = "!$HOME_NET";
    
    public Rule() {
        this.options = new HashMap<>();
    }
    
    public boolean matches(Map<String, String> packetData) {
        if (packetData == null) {
            return false;
        }

        try {
            // Vérifier le protocole
            String protocol = packetData.get("protocol");
            if (protocol == null || (!this.protocol.equals("any") && !this.protocol.equalsIgnoreCase(protocol))) {
                return false;
            }

            // Vérifier les adresses IP
            if (!matchesIpAddress(packetData.get("srcIP"), this.sourceIp) ||
                !matchesIpAddress(packetData.get("destIP"), this.destinationIp)) {
                return false;
            }

            // Vérifier les ports
            if (!matchesPort(packetData.get("srcPort"), this.sourcePort) ||
                !matchesPort(packetData.get("destPort"), this.destinationPort)) {
                return false;
            }

            // Vérifier les paramètres ICMP si c'est un paquet ICMP
            if ("ICMP".equalsIgnoreCase(protocol) && !matchesIcmpParameters(packetData)) {
                return false;
            }

            // Vérifier le contenu
            if (!matchesContent(packetData)) {
                return false;
            }

            // Vérifier les expressions régulières PCRE
            if (!matchesPcre(packetData)) {
                return false;
            }

            return true;
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error matching rule: " + e.getMessage(), e);
            return false;
        }
    }

    private boolean matchesIpAddress(String packetIp, String ruleIp) {
        if (packetIp == null || ruleIp == null || ruleIp.equals("any")) {
            return true;
        }

        // Gérer les variables prédéfinies
        if (ruleIp.equals("$HOME_NET")) {
            return isInNetwork(packetIp, HOME_NET);
        } else if (ruleIp.equals("$EXTERNAL_NET")) {
            return !isInNetwork(packetIp, HOME_NET);
        }

        // Gérer les négations
        if (ruleIp.startsWith("!")) {
            return !packetIp.equals(ruleIp.substring(1));
        }

        // Gérer les CIDR
        if (ruleIp.contains("/")) {
            return isInNetwork(packetIp, ruleIp);
        }

        return packetIp.equals(ruleIp);
    }

    private boolean matchesPort(String packetPort, String rulePort) {
        if (packetPort == null || rulePort == null || rulePort.equals("any")) {
            return true;
        }

        // Gérer les listes de ports
        if (rulePort.contains(",")) {
            String[] ports = rulePort.split(",");
            for (String port : ports) {
                if (matchesPort(packetPort, port.trim())) {
                    return true;
                }
            }
            return false;
        }

        // Gérer les plages de ports
        if (rulePort.contains(":")) {
            String[] range = rulePort.split(":");
            int min = Integer.parseInt(range[0]);
            int max = range[1].equals("") ? 65535 : Integer.parseInt(range[1]);
            int port = Integer.parseInt(packetPort);
            return port >= min && port <= max;
        }

        return packetPort.equals(rulePort);
    }

    private boolean matchesIcmpParameters(Map<String, String> packetData) {
        // Vérifier ICMP type
        String itype = this.options.get("itype");
        if (itype != null) {
            String packetItype = packetData.get("itype");
            if (packetItype == null || !itype.equals(packetItype)) {
                return false;
            }
        }

        // Vérifier ICMP code
        String icode = this.options.get("icode");
        if (icode != null) {
            String packetIcode = packetData.get("icode");
            if (packetIcode == null) {
                return false;
            }
            if (!matchesNumericComparison(packetIcode, icode)) {
                return false;
            }
        }

        // Vérifier ICMP ID
        String icmpId = this.options.get("icmp_id");
        if (icmpId != null) {
            String packetIcmpId = packetData.get("icmp_id");
            if (packetIcmpId == null || !icmpId.equals(packetIcmpId)) {
                return false;
            }
        }

        // Vérifier ICMP sequence
        String icmpSeq = this.options.get("icmp_seq");
        if (icmpSeq != null) {
            String packetIcmpSeq = packetData.get("icmp_seq");
            if (packetIcmpSeq == null || !icmpSeq.equals(packetIcmpSeq)) {
                return false;
            }
        }

        return true;
    }

    private boolean matchesContent(Map<String, String> packetData) {
        String content = this.options.get("content");
        if (content == null) {
            return true;
        }

        String data = packetData.get("data");
        String payload = packetData.get("payload");
        boolean nocase = "true".equalsIgnoreCase(this.options.get("nocase"));
        
        if (data == null && payload == null) {
            return false;
        }

        // Gérer le contenu hexadécimal
        if (content.startsWith("|") && content.endsWith("|")) {
            content = hexToString(content.substring(1, content.length() - 1));
        }

        // Vérifier avec l'option nocase
        if (nocase) {
            content = content.toLowerCase();
            if (data != null) data = data.toLowerCase();
            if (payload != null) payload = payload.toLowerCase();
        }

        // Vérifier la profondeur si spécifiée
        String depth = this.options.get("depth");
        if (depth != null) {
            int depthValue = Integer.parseInt(depth);
            if (data != null && data.length() > depthValue) {
                data = data.substring(0, depthValue);
            }
            if (payload != null && payload.length() > depthValue) {
                payload = payload.substring(0, depthValue);
            }
        }

        return (data != null && data.contains(content)) ||
               (payload != null && payload.contains(content));
    }

    private boolean matchesPcre(Map<String, String> packetData) {
        String pcre = this.options.get("pcre");
        if (pcre == null) {
            return true;
        }

        try {
            // Extraire le motif et les options de l'expression PCRE
            String pattern = pcre.substring(1, pcre.lastIndexOf('/'));
            String options = pcre.substring(pcre.lastIndexOf('/') + 1);
            
            int flags = 0;
            if (options.contains("i")) flags |= Pattern.CASE_INSENSITIVE;
            if (options.contains("s")) flags |= Pattern.DOTALL;
            if (options.contains("m")) flags |= Pattern.MULTILINE;
            
            Pattern regex = Pattern.compile(pattern, flags);
            
            String data = packetData.get("data");
            String payload = packetData.get("payload");
            
            return (data != null && regex.matcher(data).find()) ||
                   (payload != null && regex.matcher(payload).find());
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error matching PCRE: " + e.getMessage(), e);
            return false;
        }
    }

    private boolean matchesNumericComparison(String value, String comparison) {
        try {
            int numValue = Integer.parseInt(value);
            
            if (comparison.startsWith(">")) {
                int threshold = Integer.parseInt(comparison.substring(1));
                return numValue > threshold;
            } else if (comparison.startsWith("<")) {
                int threshold = Integer.parseInt(comparison.substring(1));
                return numValue < threshold;
            } else if (comparison.startsWith(">=")) {
                int threshold = Integer.parseInt(comparison.substring(2));
                return numValue >= threshold;
            } else if (comparison.startsWith("<=")) {
                int threshold = Integer.parseInt(comparison.substring(2));
                return numValue <= threshold;
            } else {
                return value.equals(comparison);
            }
        } catch (NumberFormatException e) {
            return value.equals(comparison);
        }
    }

    private boolean isInNetwork(String ip, String network) {
        try {
            String[] parts = network.split("/");
            String networkIp = parts[0];
            int cidr = Integer.parseInt(parts[1]);
            
            long networkAddr = ipToLong(networkIp);
            long ipAddr = ipToLong(ip);
            
            long mask = -1L << (32 - cidr);
            
            return (networkAddr & mask) == (ipAddr & mask);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error checking network membership: " + e.getMessage(), e);
            return false;
        }
    }

    private long ipToLong(String ip) {
        String[] octets = ip.split("\\.");
        long result = 0;
        for (int i = 0; i < 4; i++) {
            result <<= 8;
            result |= Integer.parseInt(octets[i]) & 0xFF;
        }
        return result;
    }

    private String hexToString(String hex) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            String str = hex.substring(i, i + 2);
            result.append((char) Integer.parseInt(str, 16));
        }
        return result.toString();
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