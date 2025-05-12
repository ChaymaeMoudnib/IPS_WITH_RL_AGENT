package com.example.detection;

import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.util.Set;
import java.util.HashSet;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.util.stream.Collectors;
import java.util.Arrays;

public class AnomalyDetector {
    private static final Logger LOGGER = Logger.getLogger(AnomalyDetector.class.getName());
    private final Map<String, Integer> portScanCount = new ConcurrentHashMap<>();
    private final Map<String, java.util.concurrent.atomic.AtomicInteger> bruteForceCount = new ConcurrentHashMap<>();
    private final Map<String, Integer> ddosCount = new ConcurrentHashMap<>();
    private final Map<String, Long> lastSeenTime = new ConcurrentHashMap<>();
    private final Map<String, Map<String, Integer>> ddosStats = new ConcurrentHashMap<>();
    private Alert lastAnomaly;
    
    // Constants for detection thresholds
    private static final int PORT_SCAN_THRESHOLD = 3;  // 3 ports différents
    private static final int BRUTE_FORCE_THRESHOLD = 3;
    private static final int DDOS_THRESHOLD = 15;      // Reduced from 20 to 15
    private static final long TIME_WINDOW_MS = 3000;     // 3 seconds for port scan and brute force
    private static final long DDOS_WINDOW = 4000;      // 4 seconds for DDoS detection
    private static final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    private final Map<String, Set<String>> scannedPorts = new ConcurrentHashMap<>();
    private final Map<String, Long> lastScanTime = new ConcurrentHashMap<>();

    private static final Set<String> SUSPICIOUS_PATTERNS = new HashSet<>(Arrays.asList(
        "UNION SELECT",
        "OR 1=1",
        "<script>",
        "javascript:",
        "eval(",
        "document.cookie",
        "alert(",
        "prompt(",
        "onload=",
        "onerror="
    ));

    public Alert detectAnomaly(Map<String, String> packetData) {
        String srcIP = packetData.get("srcIP");
        String protocol = packetData.get("protocol");
        String destPort = packetData.get("destPort");
        String destIP = packetData.get("destIP");
        
        if (srcIP == null || protocol == null) {
            return null;
        }

        // Reset counters if time window has expired
        long currentTime = System.currentTimeMillis();
        if (lastSeenTime.containsKey(srcIP)) {
            long timeSinceLastSeen = currentTime - lastSeenTime.get(srcIP);
            if (timeSinceLastSeen > TIME_WINDOW_MS) {
                portScanCount.remove(srcIP);
                bruteForceCount.remove(srcIP);
                scannedPorts.remove(srcIP);
            }
            if (timeSinceLastSeen > DDOS_WINDOW) {
                ddosCount.remove(srcIP);
                ddosStats.remove(srcIP);
            }
        }
        lastSeenTime.put(srcIP, currentTime);

        // Check for XSS attack first
        Alert xssAlert = detectXss(packetData);
        if (xssAlert != null) {
            return xssAlert;
        }

        // Check for port scan
        if (protocol.equals("TCP")) {
            Alert portScanAlert = detectPortScan(packetData);
            if (portScanAlert != null) {
                return portScanAlert;
            }
        }

        // Check for brute force attempts
        if (protocol.equals("TCP") && 
            (destPort.equals("22") || destPort.equals("445") || destPort.equals("3389"))) {
            Alert bruteForceAlert = detectBruteForce(packetData);
            if (bruteForceAlert != null) {
                return bruteForceAlert;
            }
        }

        // Check for abnormal traffic
        return detectAbnormalTraffic(packetData);
    }

    private Alert detectXss(Map<String, String> packetData) {
        String data = packetData.get("data");
        if (data != null && (data.contains("<script>") || data.contains("javascript:"))) {
            StringBuilder message = new StringBuilder();
            message.append(String.format("XSS Attack Detected! Source: %s\n", packetData.get("srcIP")));
            message.append(String.format("Target: %s\n", packetData.get("destIP")));
            message.append(String.format("Payload: %s\n", data));
            
            LOGGER.warning(message.toString());
            
            return new Alert(
                AlertType.XSS_ATTACK,
                Severity.HIGH,
                message.toString(),
                new HashMap<>(packetData)
            );
        }
        return null;
    }

    private Alert detectPortScan(Map<String, String> packetData) {
        String srcIP = packetData.get("srcIP");
        String destPort = packetData.get("destPort");
        long now = System.currentTimeMillis();

        if (srcIP == null || destPort == null) return null;

        scannedPorts.putIfAbsent(srcIP, new HashSet<>());
        lastScanTime.putIfAbsent(srcIP, now);

        // Reset si la fenêtre est dépassée
        if (now - lastScanTime.get(srcIP) > TIME_WINDOW_MS) {
            scannedPorts.get(srcIP).clear();
            lastScanTime.put(srcIP, now);
        }

        scannedPorts.get(srcIP).add(destPort);

        if (scannedPorts.get(srcIP).size() >= PORT_SCAN_THRESHOLD) {
            Alert alert = new Alert(
                AlertType.PORT_SCAN,
                Severity.HIGH,
                "Port scan detected from " + srcIP + " (" + scannedPorts.get(srcIP).size() + " ports)",
                new HashMap<>(packetData)
            );
            scannedPorts.get(srcIP).clear();
            lastScanTime.put(srcIP, now);
            return alert;
        }
        return null;
    }

    private Alert detectBruteForce(Map<String, String> packetData) {
        String srcIP = packetData.get("srcIP");
        String destPort = packetData.get("destPort");
        String protocol = packetData.get("protocol");
        
        if (protocol.equals("TCP") && 
            (destPort.equals("22") || destPort.equals("445") || destPort.equals("3389"))) {
            AtomicInteger count = bruteForceCount.computeIfAbsent(srcIP, k -> new AtomicInteger(0));
            if (count.incrementAndGet() >= BRUTE_FORCE_THRESHOLD) {
                return new Alert(
                    AlertType.BRUTE_FORCE,
                    Severity.CRITICAL,
                    "Brute force attempt detected from " + srcIP + " on port " + destPort,
                    new HashMap<>(Map.of(
                        "srcIP", srcIP,
                        "destPort", destPort,
                        "protocol", protocol,
                        "count", String.valueOf(count.get())
                    ))
                );
            }
        }
        return null;
    }

    public Alert detectAbnormalTraffic(Map<String, String> packet) {
        if (packet == null) return null;
        
        String data = packet.get("data");
        String payload = packet.get("payload");
        
        // Si ni data ni payload n'est présent, pas besoin de vérifier le contenu
        if (data == null && payload == null) {
            return null;
        }
        
        // Vérifier le contenu si présent
        String contentToCheck = data != null ? data : payload;
        if (contentToCheck != null && !contentToCheck.isEmpty()) {
            // Vérifier les motifs suspects
            if (containsSuspiciousPatterns(contentToCheck)) {
                return createAlert(AlertType.SUSPICIOUS_CONTENT, Severity.HIGH, 
                    "Suspicious content detected", packet);
            }
        }
        
        return null;
    }

    private boolean containsSuspiciousPatterns(String content) {
        if (content == null || content.isEmpty()) {
            return false;
        }
        
        // Vérifier les motifs suspects
        for (String pattern : SUSPICIOUS_PATTERNS) {
            if (content.toLowerCase().contains(pattern.toLowerCase())) {
                return true;
            }
        }
        
        return false;
    }

    private Alert createAlert(AlertType type, Severity severity, String message, Map<String, String> packet) {
        return new Alert(type, severity, message, new HashMap<>(packet));
    }

    public Alert getLastAnomaly() {
        return lastAnomaly;
    }
} 