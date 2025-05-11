package com.example;

import com.example.rl.RLAgent;
import com.example.rl.State;
import com.example.rl.Action;
import com.example.util.PacketParser;

import java.util.Map;
import java.util.HashMap;
import java.util.function.Consumer;

public class IDPSController {
    private final RLAgent rlAgent;
    private Consumer<String> decisionCallback;
    private Consumer<Map<String, Object>> statsCallback;
    
    public IDPSController() {
        this.rlAgent = new RLAgent();
    }
    
    public void setDecisionCallback(Consumer<String> callback) {
        this.decisionCallback = callback;
    }
    
    public void setStatsCallback(Consumer<Map<String, Object>> callback) {
        this.statsCallback = callback;
    }
    
    public boolean processPacket(Map<String, String> packetData) {
        // Extraire les features pertinentes
        String protocol = packetData.getOrDefault("protocol", "UNKNOWN");
        String srcPort = packetData.getOrDefault("srcPort", "0");
        String srcIP = packetData.getOrDefault("srcIP", "0.0.0.0");
        String destPort = packetData.getOrDefault("destPort", "0");
        String destIP = packetData.getOrDefault("destIP", "0.0.0.0");
        
        // Créer l'état pour le RL
        State currentState = new State(protocol, srcPort, srcIP, destPort, destIP);
        
        // Obtenir la décision du RL
        Action action = rlAgent.getAction(currentState);
        boolean allow = action.isAllowed();
        
        // Notifier l'interface des décisions
        if (decisionCallback != null) {
            String decision = String.format("[%s] %s -> %s:%s (%s) : %s",
                protocol, srcIP, destIP, destPort,
                allow ? "ALLOWED" : "BLOCKED",
                action.getConfidence());
            decisionCallback.accept(decision);
        }
        
        // Mettre à jour les statistiques
        if (statsCallback != null) {
            Map<String, Object> stats = new HashMap<>();
            stats.put("allowedCount", rlAgent.getAllowedCount());
            stats.put("blockedCount", rlAgent.getBlockedCount());
            stats.put("confidence", action.getConfidence());
            statsCallback.accept(stats);
        }
        
        return allow;
    }
    
    public void train(String csvFile) {
        rlAgent.train(csvFile);
    }

    /**
     * Récupère les statistiques actuelles du système
     * @return Map contenant les statistiques
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("allowedCount", rlAgent.getAllowedCount());
        stats.put("blockedCount", rlAgent.getBlockedCount());
        
        // Obtenir la dernière action pour sa confiance
        Action lastAction = rlAgent.getLastAction();
        stats.put("confidence", lastAction != null ? lastAction.getConfidence() : 0.0);
        
        return stats;
    }
} 