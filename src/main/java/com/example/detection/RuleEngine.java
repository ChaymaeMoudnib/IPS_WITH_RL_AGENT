package com.example.detection;

import com.example.util.Rule;
import com.example.util.RuleLoader;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.logging.Logger;
import java.util.logging.Level;

public class RuleEngine {
    private static final Logger LOGGER = Logger.getLogger(RuleEngine.class.getName());
    private final List<Rule> rules;
    private final Map<String, List<Rule>> protocolRules;
    private final RuleLoader ruleLoader;
    private String homeNet;
    private String externalNet;
    private final Pattern portRangePattern;
    private final Pattern ipCidrPattern;
    
    private static final Map<String, Integer> SERVICE_PORTS;
    static {
        Map<String, Integer> ports = new HashMap<>();
        ports.put("http", 80);
        ports.put("https", 443);
        ports.put("ftp", 21);
        ports.put("ssh", 22);
        ports.put("telnet", 23);
        ports.put("smtp", 25);
        ports.put("dns", 53);
        SERVICE_PORTS = Collections.unmodifiableMap(ports);
    }

    private Rule lastMatchedRule;

    public RuleEngine() {
        this.ruleLoader = new RuleLoader();
        this.rules = new ArrayList<>();
        this.protocolRules = new HashMap<>();
        this.homeNet = "192.168.0.0/16"; // Default home network
        this.externalNet = "0.0.0.0/0";   // Default external network
        this.portRangePattern = Pattern.compile("(\\d+)(?::(\\d+))?");
        this.ipCidrPattern = Pattern.compile("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})(?:/(\\d{1,2}))?");
        loadRules();
    }

    public void setHomeNet(String homeNet) {
        this.homeNet = homeNet;
    }

    public void setExternalNet(String externalNet) {
        this.externalNet = externalNet;
    }

    private void loadRules() {
        try {
            List<Rule> loadedRules = ruleLoader.getRules();
            rules.addAll(loadedRules);
            
            LOGGER.info("Loaded " + loadedRules.size() + " rules successfully");

            // Index rules by protocol for faster matching
            for (Rule rule : loadedRules) {
                String protocol = rule.getProtocol();
                protocolRules.computeIfAbsent(protocol, k -> new ArrayList<>()).add(rule);
            }
            
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error loading rules", e);
        }
    }

    public List<Rule> getMatchingRules(Map<String, String> packet) {
            if (packet == null || packet.isEmpty()) {
                return Collections.emptyList();
            }

        try {
            List<Rule> matches = new ArrayList<>();
            String protocol = packet.getOrDefault("protocol", "UNKNOWN").toUpperCase();
            
            List<Rule> candidateRules = new ArrayList<>();
            candidateRules.addAll(protocolRules.getOrDefault(protocol, Collections.emptyList()));
            candidateRules.addAll(protocolRules.getOrDefault("any", Collections.emptyList()));
            
            for (Rule rule : candidateRules) {
                if (matches(packet, rule)) {
                    matches.add(rule);
                }
            }
            
            return matches;
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }

    private boolean matches(Map<String, String> packet, Rule rule) {
        if (packet == null || rule == null) return false;

        try {
            if (!matchesProtocol(packet, rule)) return false;
            if (!matchesIpAddresses(packet, rule)) return false;
            if (!matchesPorts(packet, rule)) return false;

            String content = rule.getOptions().get("content");
            if (content != null) {
                String data = packet.get("data");
                String payload = packet.get("payload");
                
                if (data == null && payload == null) return false;

                boolean contentMatched = false;
                if (data != null && data.contains(content)) {
                    contentMatched = true;
                }
                if (payload != null && payload.contains(content)) {
                    contentMatched = true;
                }

                if (!contentMatched) return false;
                }

        return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    private boolean matchesProtocol(Map<String, String> packet, Rule rule) {
        String ruleProtocol = rule.getProtocol();
        String packetProtocol = packet.getOrDefault("protocol", "UNKNOWN");
        
        if (ruleProtocol == null) return false;
        
        // Handle protocol aliases
        if (ruleProtocol.equalsIgnoreCase("tcp") && 
            (packetProtocol.equalsIgnoreCase("http") || 
             packetProtocol.equalsIgnoreCase("https"))) {
            return true;
        }
        
        return ruleProtocol.equalsIgnoreCase(packetProtocol);
    }

    private boolean matchesIpAddresses(Map<String, String> packet, Rule rule) {
        return matchesIp(packet.getOrDefault("srcIP", "0.0.0.0"), rule.getSourceIp()) &&
               matchesIp(packet.getOrDefault("destIP", "0.0.0.0"), rule.getDestinationIp());
    }
    
    private boolean matchesIp(String packetIp, String ruleIp) {
        if (ruleIp == null || ruleIp.equals("any")) return true;
        
        try {
            if (ruleIp.equals("$HOME_NET")) {
                return isInNetwork(packetIp, homeNet);
            } else if (ruleIp.equals("$EXTERNAL_NET")) {
                return isInNetwork(packetIp, externalNet);
            }
            
            // Handle CIDR notation
            Matcher matcher = ipCidrPattern.matcher(ruleIp);
            if (matcher.matches()) {
                String ip = matcher.group(1);
                String cidr = matcher.group(2);
                return isInNetwork(packetIp, ip + (cidr != null ? "/" + cidr : "/32"));
            }
            
            return ruleIp.equals(packetIp);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error matching IP: " + packetIp + " against " + ruleIp, e);
            return false;
        }
    }
    
    private boolean matchesPorts(Map<String, String> packet, Rule rule) {
        return matchesPort(packet.getOrDefault("srcPort", "0"), rule.getSourcePort()) &&
               matchesPort(packet.getOrDefault("destPort", "0"), rule.getDestinationPort());
    }
    
    private boolean matchesPort(String packetPort, String rulePort) {
        if (rulePort == null || rulePort.equals("any")) return true;
        
        try {
            // Nettoyer le port d'entrée (enlever les parenthèses et texte)
            String cleanPacketPort = packetPort.replaceAll("\\s*\\([^)]*\\)", "").trim();
            int port = Integer.parseInt(cleanPacketPort);
            
            // Handle service names
            if (SERVICE_PORTS.containsKey(rulePort.toLowerCase())) {
                return port == SERVICE_PORTS.get(rulePort.toLowerCase());
            }
            
            // Handle port ranges
            Matcher matcher = portRangePattern.matcher(rulePort);
            if (matcher.matches()) {
                int start = Integer.parseInt(matcher.group(1));
                String endStr = matcher.group(2);
                if (endStr != null) {
                    int end = Integer.parseInt(endStr);
                    return port >= start && port <= end;
                }
                return port == start;
            }
            
            // Try direct port number comparison
            return port == Integer.parseInt(rulePort);
        } catch (Exception e) {
        return false;
        }
    }

    private boolean matchesFlow(Map<String, String> packet, Rule rule) {
        String flow = rule.getOptions().get("flow");
        if (flow == null) return true;
        
        try {
            String[] flowOptions = flow.split(",");
            for (String option : flowOptions) {
                option = option.trim();
                switch (option) {
                    case "established":
                        if (!isEstablishedConnection(packet)) return false;
                        break;
                    case "to_server":
                        if (!isToServer(packet)) return false;
                        break;
                    case "to_client":
                        if (!isToClient(packet)) return false;
                        break;
                    case "stateless":
                        // No state checking needed
                        break;
                }
            }
            return true;
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error matching flow", e);
            return false;
        }
    }
    
    private boolean matchesContent(Map<String, String> packet, Rule rule) {
        String content = rule.getOptions().get("content");
        if (content == null) return true;
        
        try {
            String payload = packet.getOrDefault("data", "");
            if (payload.isEmpty()) return false;
            
            // Handle hex content
            if (content.startsWith("|") && content.endsWith("|")) {
                content = content.substring(1, content.length() - 1);
                // Convert hex string to bytes and compare
                return payload.contains(hexToString(content));
            }
            
            // Handle case sensitivity
            if (rule.getOptions().containsKey("nocase")) {
                return payload.toLowerCase().contains(content.toLowerCase());
            }
            
            return payload.contains(content);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error matching content", e);
            return false;
        }
    }
    
    private boolean matchesFlags(Map<String, String> packet, Rule rule) {
        String flags = rule.getOptions().get("flags");
        if (flags == null) return true;
        
        try {
            String packetFlags = packet.getOrDefault("tcpFlags", "");
            if (packetFlags.isEmpty()) return false;
            
            // Convert flag strings to sets for comparison
            Set<Character> ruleFlags = new HashSet<>();
            Set<Character> pktFlags = new HashSet<>();
            
            for (char flag : flags.toCharArray()) ruleFlags.add(flag);
            for (char flag : packetFlags.toCharArray()) pktFlags.add(flag);
            
            return pktFlags.containsAll(ruleFlags);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error matching flags", e);
            return false;
        }
    }

    private boolean isInNetwork(String ip, String network) {
        try {
            String[] parts = network.split("/");
            byte[] addr = InetAddress.getByName(ip).getAddress();
            byte[] subnet = InetAddress.getByName(parts[0]).getAddress();
            int cidr = parts.length > 1 ? Integer.parseInt(parts[1]) : 32;
            
            int mask = -1 << (32 - cidr);
            
            int ipInt = ((addr[0] & 0xFF) << 24) |
                       ((addr[1] & 0xFF) << 16) |
                       ((addr[2] & 0xFF) << 8)  |
                       ((addr[3] & 0xFF));
                       
            int subnetInt = ((subnet[0] & 0xFF) << 24) |
                          ((subnet[1] & 0xFF) << 16) |
                          ((subnet[2] & 0xFF) << 8)  |
                          ((subnet[3] & 0xFF));
                          
            return (ipInt & mask) == (subnetInt & mask);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error checking network membership", e);
            return false;
        }
    }

    private boolean isEstablishedConnection(Map<String, String> packet) {
        String flags = packet.getOrDefault("tcpFlags", "");
        return flags.contains("A") && (flags.contains("S") || flags.contains("F"));
    }

    private boolean isToServer(Map<String, String> packet) {
        String destPort = packet.getOrDefault("destPort", "0");
        try {
            int port = Integer.parseInt(destPort);
            return port < 1024;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private boolean isToClient(Map<String, String> packet) {
        String srcPort = packet.getOrDefault("srcPort", "0");
        try {
            int port = Integer.parseInt(srcPort);
            return port < 1024;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private String hexToString(String hex) {
        try {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hex.length(); i += 2) {
                String hexByte = hex.substring(i, i + 2);
                sb.append((char) Integer.parseInt(hexByte, 16));
            }
            return sb.toString();
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error converting hex to string", e);
            return "";
        }
    }

    public void addRule(Rule rule) {
        if (rule != null) {
            String protocol = rule.getProtocol();
            protocolRules.computeIfAbsent(protocol, k -> new ArrayList<>()).add(rule);
            rules.add(rule);
        }
    }

    public void setRules(List<Rule> newRules) {
        rules.clear();
        protocolRules.clear();
        if (newRules != null) {
            rules.addAll(newRules);
            for (Rule rule : newRules) {
                String protocol = rule.getProtocol();
                protocolRules.computeIfAbsent(protocol, k -> new ArrayList<>()).add(rule);
            }
        }
    }

    public List<Rule> getRules() {
        return Collections.unmodifiableList(rules);
    }

    public boolean matches(Map<String, String> packet) {
        List<Rule> matches = getMatchingRules(packet);
        if (!matches.isEmpty()) {
            lastMatchedRule = matches.get(0);
            return true;
        }
        return false;
    }

    public Rule getLastMatchedRule() {
        return lastMatchedRule;
    }
} 