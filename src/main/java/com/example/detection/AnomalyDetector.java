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

public class AnomalyDetector {
    private static final Logger LOGGER = Logger.getLogger(AnomalyDetector.class.getName());
    private final Map<String, AtomicInteger> portScanCount;
    private final Map<String, AtomicInteger> bruteForceCount;
    private final Map<String, AtomicInteger> ddosCount;
    private final Map<String, Long> lastSeen;
    private final Map<String, Set<String>> scannedPorts;
    private final Map<String, Map<String, Integer>> ddosStats;
    private Alert lastAnomaly;
    
    private static final int PORT_SCAN_THRESHOLD = 3;
    private static final int BRUTE_FORCE_THRESHOLD = 3;
    private static final int DDOS_THRESHOLD = 15;
    private static final long TIME_WINDOW = 30000; // 30 secondes
    private static final long DDOS_WINDOW = 4000; // 4 secondes pour correspondre à la simulation
    private static final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public AnomalyDetector() {
        this.portScanCount = new ConcurrentHashMap<>();
        this.bruteForceCount = new ConcurrentHashMap<>();
        this.ddosCount = new ConcurrentHashMap<>();
        this.lastSeen = new ConcurrentHashMap<>();
        this.scannedPorts = new ConcurrentHashMap<>();
        this.ddosStats = new ConcurrentHashMap<>();
    }

    public Alert detectAnomaly(Map<String, String> packet) {
        try {
            if (packet == null || packet.isEmpty()) {
                LOGGER.warning("Received empty packet data");
                return null;
            }

            String srcIP = packet.getOrDefault("srcIP", "0.0.0.0");
            String destPort = packet.getOrDefault("destPort", "0");
            String protocol = packet.getOrDefault("protocol", "UNKNOWN");
            long currentTime = System.currentTimeMillis();

            // Réinitialiser les compteurs si la fenêtre de temps est dépassée
            if (lastSeen.containsKey(srcIP)) {
                long timeSinceLastSeen = currentTime - lastSeen.get(srcIP);
                if (timeSinceLastSeen > TIME_WINDOW) {
                    portScanCount.remove(srcIP);
                    bruteForceCount.remove(srcIP);
                    scannedPorts.remove(srcIP);
                }
                if (timeSinceLastSeen > DDOS_WINDOW) {
                    ddosCount.remove(srcIP);
                }
            }
            lastSeen.put(srcIP, currentTime);

            // Détection DDoS
            Alert ddosAlert = detectDDoS(srcIP, packet);
            if (ddosAlert != null) {
                LOGGER.info("DDoS attack detected from " + srcIP);
                lastAnomaly = ddosAlert;
                return ddosAlert;
            }

            // Détection de scan de ports
            Alert portScanAlert = detectPortScan(srcIP, destPort, protocol);
            if (portScanAlert != null) {
                LOGGER.info("Port scan detected from " + srcIP);
                lastAnomaly = portScanAlert;
                return portScanAlert;
            }

            // Détection de force brute
            Alert bruteForceAlert = detectBruteForce(srcIP, destPort, protocol);
            if (bruteForceAlert != null) {
                LOGGER.info("Brute force attempt detected from " + srcIP);
                lastAnomaly = bruteForceAlert;
                return bruteForceAlert;
            }

            // Détection de trafic anormal
            Alert abnormalTrafficAlert = detectAbnormalTraffic(packet);
            if (abnormalTrafficAlert != null) {
                LOGGER.info("Abnormal traffic detected");
                lastAnomaly = abnormalTrafficAlert;
                return abnormalTrafficAlert;
            }

            return null;
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error detecting anomaly", e);
            return null;
        }
    }

    private Alert detectDDoS(String srcIP, Map<String, String> packet) {
        String protocol = packet.getOrDefault("protocol", "UNKNOWN");
        String destPort = packet.getOrDefault("destPort", "0");
        String destIP = packet.getOrDefault("destIP", "0.0.0.0");
        
        if (protocol.equals("TCP")) {
            // Mettre à jour les statistiques DDoS
            Map<String, Integer> stats = ddosStats.computeIfAbsent(srcIP, k -> new HashMap<>());
            stats.put("totalPackets", stats.getOrDefault("totalPackets", 0) + 1);
            stats.put("targetPorts", stats.getOrDefault("targetPorts", 0) + 1);
            
            // Vérifier le seuil DDoS
            AtomicInteger count = ddosCount.computeIfAbsent(srcIP, k -> new AtomicInteger(0));
            int currentCount = count.incrementAndGet();
            
            if (currentCount >= DDOS_THRESHOLD) {
                StringBuilder alertMessage = new StringBuilder();
                alertMessage.append("DDoS attack detected!\n");
                alertMessage.append("Source IP: ").append(srcIP).append("\n");
                alertMessage.append("Target IP: ").append(destIP).append("\n");
                alertMessage.append("Protocol: ").append(protocol).append("\n");
                alertMessage.append("Packets in last ").append(DDOS_WINDOW/1000).append(" seconds: ").append(currentCount).append("\n");
                alertMessage.append("Total packets: ").append(stats.get("totalPackets")).append("\n");
                alertMessage.append("Timestamp: ").append(dateFormat.format(new Date())).append("\n");
                
                LOGGER.warning(alertMessage.toString());
                
                Map<String, String> alertData = new HashMap<>(packet);
                alertData.put("totalPackets", String.valueOf(stats.get("totalPackets")));
                alertData.put("windowPackets", String.valueOf(currentCount));
                alertData.put("timestamp", dateFormat.format(new Date()));
                
                return new Alert(
                    AlertType.DDOS_ATTACK,
                    Severity.CRITICAL,
                    alertMessage.toString(),
                    alertData
                );
            }
        }
        return null;
    }

    private Alert detectPortScan(String srcIP, String destPort, String protocol) {
        if (protocol.equals("TCP")) {
            Set<String> ports = scannedPorts.computeIfAbsent(srcIP, k -> new HashSet<>());
            ports.add(destPort); // Ajouter le port à l'ensemble des ports scannés
            
            // Incrémenter le compteur de tentatives
            AtomicInteger count = portScanCount.computeIfAbsent(srcIP, k -> new AtomicInteger(0));
            int currentCount = count.incrementAndGet();
            
            // Vérifier si nous avons atteint le seuil de ports uniques
            if (ports.size() >= PORT_SCAN_THRESHOLD) {
                StringBuilder alertMessage = new StringBuilder();
                alertMessage.append("Port scan detected!\n");
                alertMessage.append("Source IP: ").append(srcIP).append("\n");
                alertMessage.append("Unique ports scanned: ").append(ports.size()).append("\n");
                alertMessage.append("Latest port: ").append(destPort).append("\n");
                alertMessage.append("Total attempts: ").append(currentCount).append("\n");
                alertMessage.append("Timestamp: ").append(dateFormat.format(new Date())).append("\n");
                
                LOGGER.warning(alertMessage.toString());
                
                Map<String, String> alertData = new HashMap<>();
                alertData.put("srcIP", srcIP);
                alertData.put("destPort", destPort);
                alertData.put("protocol", protocol);
                alertData.put("uniquePorts", String.valueOf(ports.size()));
                alertData.put("totalAttempts", String.valueOf(currentCount));
                alertData.put("timestamp", dateFormat.format(new Date()));
                
                // Réinitialiser les compteurs après la détection
                portScanCount.remove(srcIP);
                scannedPorts.remove(srcIP);
                
                return new Alert(
                    AlertType.PORT_SCAN,
                    Severity.HIGH,
                    alertMessage.toString(),
                    alertData
                );
            }
        }
        return null;
    }

    private Alert detectBruteForce(String srcIP, String destPort, String protocol) {
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

    private Alert detectAbnormalTraffic(Map<String, String> packet) {
        String protocol = packet.getOrDefault("protocol", "UNKNOWN");
        String destPort = packet.getOrDefault("destPort", "0");
        String data = packet.getOrDefault("data", "");

        // Détection de trafic chiffré suspect
        if (protocol.equals("TCP") && 
            (destPort.equals("8443") || destPort.equals("4443"))) {
            return new Alert(
                AlertType.SUSPICIOUS_TRAFFIC,
                Severity.HIGH,
                "Suspicious encrypted traffic detected on port " + destPort,
                new HashMap<>(packet)
            );
        }

        // Détection de contenu suspect
        if (!data.isEmpty()) {
            if (data.contains("UNION SELECT") || data.contains("OR 1=1")) {
                return new Alert(
                    AlertType.SQL_INJECTION,
                    Severity.CRITICAL,
                    "SQL injection attempt detected",
                    new HashMap<>(packet)
                );
            }
            if (data.contains("<script>") || data.contains("javascript:")) {
                return new Alert(
                    AlertType.XSS_ATTACK,
                    Severity.HIGH,
                    "XSS attack attempt detected",
                    new HashMap<>(packet)
                );
            }
        }

        return null;
    }

    public Alert getLastAnomaly() {
        return lastAnomaly;
    }
} 