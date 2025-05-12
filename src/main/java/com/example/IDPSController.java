package com.example;

import com.example.rl.RLAgent;
import com.example.rl.State;
import com.example.rl.Action;
import com.example.util.PacketParser;
import com.example.logging.AlertLogger;
import com.example.detection.AnomalyDetector;

import java.util.Map;
import java.util.HashMap;
import java.util.function.Consumer;
import java.util.logging.Logger;
import java.util.logging.Level;

public class IDPSController {
    private static final Logger LOGGER = Logger.getLogger(IDPSController.class.getName());
    private final RLAgent rlAgent;
    private Consumer<String> decisionCallback;
    private Consumer<Map<String, Object>> statsCallback;
    private final AlertLogger alertLogger;
    private AnomalyDetector anomalyDetector;
    
    public IDPSController() {
        this.rlAgent = new RLAgent();
        try {
            this.anomalyDetector = new AnomalyDetector();
            this.alertLogger = new AlertLogger();
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error initializing AlertLogger", e);
            throw new RuntimeException("Failed to initialize IDPSController", e);
        }
    }
    
    public void setDecisionCallback(Consumer<String> callback) {
        this.decisionCallback = callback;
    }
    
    public void setStatsCallback(Consumer<Map<String, Object>> callback) {
        this.statsCallback = callback;
    }
    
    public boolean processPacket(Map<String, String> packetData) {
        try {
            if (packetData == null || packetData.isEmpty()) {
                LOGGER.warning("Received empty packet data");
                return false;
            }

            // Extraire les features pertinentes avec validation
            String protocol = validateField(packetData.get("protocol"), "UNKNOWN");
            String srcPort = validateField(packetData.get("srcPort"), "0");
            String srcIP = validateField(packetData.get("srcIP"), "0.0.0.0");
            String destPort = validateField(packetData.get("destPort"), "0");
            String destIP = validateField(packetData.get("destIP"), "0.0.0.0");
            
            // Créer l'état pour le RL
            State currentState = new State(protocol, srcPort, srcIP, destPort, destIP);
            
            // Obtenir la décision du RL
            Action action = rlAgent.getAction(currentState);
            boolean allow = action.isAllowed();
            
            notifyDecision(protocol, srcIP, destIP, destPort, allow, action);
            updateStatistics(action);
            
            return allow;
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error processing packet", e);
            return false;
        }
    }

    private String validateField(String value, String defaultValue) {
        return value != null && !value.trim().isEmpty() ? value : defaultValue;
    }

    private void notifyDecision(String protocol, String srcIP, String destIP, String destPort, 
                              boolean allow, Action action) {
        if (decisionCallback != null) {
            String decision = String.format("[%s] %s -> %s:%s (%s) : %.2f",
                protocol, srcIP, destIP, destPort,
                allow ? "ALLOWED" : "BLOCKED",
                action.getConfidence());
            decisionCallback.accept(decision);
        }
    }

    private void updateStatistics(Action action) {
        if (statsCallback != null) {
            Map<String, Object> stats = new HashMap<>();
            int allowedCount = rlAgent.getAllowedCount();
            int blockedCount = rlAgent.getBlockedCount();
            int totalPackets = allowedCount + blockedCount;
            
            stats.put("allowedCount", allowedCount);
            stats.put("blockedCount", blockedCount);
            
            // Calculer l'accuracy
            double accuracy = totalPackets > 0 ? 
                ((double) (allowedCount + blockedCount) / totalPackets) * 100 : 0.0;
            stats.put("accuracy", accuracy);
            
            statsCallback.accept(stats);
        }
    }
    
    public void train(String csvFile) {
        try {
            rlAgent.train(csvFile);
            LOGGER.info("Training completed successfully");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Training failed", e);
            throw new RuntimeException("Training failed", e);
        }
    }

    /**
     * Récupère les statistiques actuelles du système
     * @return Map contenant les statistiques
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        int allowedCount = rlAgent.getAllowedCount();
        int blockedCount = rlAgent.getBlockedCount();
        int totalPackets = allowedCount + blockedCount;
        
        stats.put("allowedCount", allowedCount);
        stats.put("blockedCount", blockedCount);
        
        // Calculer l'accuracy
        double accuracy = totalPackets > 0 ? 
            ((double) (allowedCount + blockedCount) / totalPackets) * 100 : 0.0;
        stats.put("accuracy", accuracy);
        
        return stats;
    }

    public void close() {
        try {
            if (alertLogger != null) {
                alertLogger.close();
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error closing AlertLogger", e);
        }
    }

    public AnomalyDetector getAnomalyDetector() {
        return anomalyDetector;
    }
} 