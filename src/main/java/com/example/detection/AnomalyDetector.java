package com.example.detection;

import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class AnomalyDetector {
    private final Map<String, AtomicInteger> portScanCount;
    private final Map<String, AtomicInteger> bruteForceCount;
    private final Map<String, Long> lastSeen;
    private Alert lastAnomaly;
    
    private static final int PORT_SCAN_THRESHOLD = 10;
    private static final int BRUTE_FORCE_THRESHOLD = 5;
    private static final long TIME_WINDOW = 60000; // 1 minute

    public AnomalyDetector() {
        this.portScanCount = new ConcurrentHashMap<>();
        this.bruteForceCount = new ConcurrentHashMap<>();
        this.lastSeen = new ConcurrentHashMap<>();
    }

    public boolean detectAnomaly(Map<String, String> packet) {
        String srcIp = packet.get("srcIp");
        String dstPort = packet.get("dstPort");
        String protocol = packet.get("protocol");
        long currentTime = System.currentTimeMillis();

        // Réinitialiser les compteurs si la fenêtre de temps est dépassée
        if (lastSeen.containsKey(srcIp) && 
            currentTime - lastSeen.get(srcIp) > TIME_WINDOW) {
            portScanCount.remove(srcIp);
            bruteForceCount.remove(srcIp);
        }
        lastSeen.put(srcIp, currentTime);

        // Détection de scan de ports
        if (detectPortScan(srcIp, dstPort, protocol)) {
            return true;
        }

        // Détection de force brute
        if (detectBruteForce(srcIp, dstPort, protocol)) {
            return true;
        }

        // Détection de trafic anormal
        if (detectAbnormalTraffic(packet)) {
            return true;
        }

        return false;
    }

    private boolean detectPortScan(String srcIp, String dstPort, String protocol) {
        if (protocol.equals("TCP")) {
            AtomicInteger count = portScanCount.computeIfAbsent(srcIp, k -> new AtomicInteger(0));
            if (count.incrementAndGet() >= PORT_SCAN_THRESHOLD) {
                lastAnomaly = new Alert(
                    AlertType.PORT_SCAN,
                    Severity.HIGH,
                    "Port scan detected from " + srcIp
                );
                return true;
            }
        }
        return false;
    }

    private boolean detectBruteForce(String srcIp, String dstPort, String protocol) {
        if (protocol.equals("TCP") && 
            (dstPort.equals("22") || dstPort.equals("445") || dstPort.equals("3389"))) {
            AtomicInteger count = bruteForceCount.computeIfAbsent(srcIp, k -> new AtomicInteger(0));
            if (count.incrementAndGet() >= BRUTE_FORCE_THRESHOLD) {
                lastAnomaly = new Alert(
                    AlertType.BRUTE_FORCE,
                    Severity.CRITICAL,
                    "Brute force attempt detected from " + srcIp + " on port " + dstPort
                );
                return true;
            }
        }
        return false;
    }

    private boolean detectAbnormalTraffic(Map<String, String> packet) {
        String protocol = packet.get("protocol");
        String dstPort = packet.get("dstPort");
        String data = packet.get("data");

        // Détection de trafic chiffré suspect
        if (protocol.equals("TCP") && 
            (dstPort.equals("8443") || dstPort.equals("4443"))) {
            lastAnomaly = new Alert(
                AlertType.SUSPICIOUS_TRAFFIC,
                Severity.HIGH,
                "Suspicious encrypted traffic detected on port " + dstPort
            );
            return true;
        }

        // Détection de contenu suspect
        if (data != null) {
            if (data.contains("UNION SELECT") || data.contains("OR 1=1")) {
                lastAnomaly = new Alert(
                    AlertType.SQL_INJECTION,
                    Severity.CRITICAL,
                    "SQL injection attempt detected"
                );
                return true;
            }
            if (data.contains("<script>") || data.contains("javascript:")) {
                lastAnomaly = new Alert(
                    AlertType.XSS_ATTACK,
                    Severity.HIGH,
                    "XSS attack attempt detected"
                );
                return true;
            }
        }

        return false;
    }

    public Alert getLastAnomaly() {
        return lastAnomaly;
    }
} 