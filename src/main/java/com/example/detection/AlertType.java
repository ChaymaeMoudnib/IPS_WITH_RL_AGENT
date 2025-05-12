package com.example.detection;

public enum AlertType {
    // Alertes de scan
    PORT_SCAN("Port Scan"),
    STEALTH_SCAN("Stealth Scan"),
    ICMP_SCAN("ICMP Scan"),
    
    // Alertes de force brute
    BRUTE_FORCE("Brute Force"),
    SSH_BRUTE_FORCE("SSH Brute Force"),
    SMB_BRUTE_FORCE("SMB Brute Force"),
    RDP_BRUTE_FORCE("RDP Brute Force"),
    
    // Alertes d'injection
    SQL_INJECTION("SQL Injection"),
    XSS_ATTACK("XSS Attack"),
    COMMAND_INJECTION("Command Injection"),
    
    // Alertes de malware
    MALWARE_TRAFFIC("Malware Traffic"),
    BOTNET_TRAFFIC("Botnet Traffic"),
    BACKDOOR_TRAFFIC("Backdoor Traffic"),
    
    // Alertes de DoS
    DOS_ATTACK("DoS Attack"),
    DDOS_ATTACK("DDoS Attack"),
    ICMP_FLOOD("ICMP Flood"),
    
    // Alertes de trafic suspect
    SUSPICIOUS_TRAFFIC("Suspicious Traffic"),
    ENCRYPTED_TRAFFIC("Encrypted Traffic"),
    UNKNOWN_TRAFFIC("Unknown Traffic"),
    
    // Alertes de reconnaissance
    RECONNAISSANCE("Reconnaissance"),
    SERVER_SCAN("Server Scan"),
    VULNERABILITY_SCAN("Vulnerability Scan"),
    
    // Nouvelle constante
    RULE_MATCH("Rule Match");

    private final String description;

    AlertType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return description;
    }
} 