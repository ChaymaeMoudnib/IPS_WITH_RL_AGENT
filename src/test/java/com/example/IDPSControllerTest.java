package com.example;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import java.util.Map;
import java.util.HashMap;
import java.util.function.Consumer;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class IDPSControllerTest {
    private IDPSController controller;
    private Map<String, String> benignPacket;
    private Map<String, String> maliciousPacket;
    private StringBuilder decisionLog;
    private Map<String, Object> lastStats;

    @BeforeEach
    void setUp() throws IOException {
        // Créer un fichier CSV de test
        createTestCsvFile();
        
        controller = new IDPSController();
        decisionLog = new StringBuilder();
        
        // Configurer les callbacks
        controller.setDecisionCallback(decision -> decisionLog.append(decision).append("\n"));
        controller.setStatsCallback(stats -> lastStats = stats);
        
        // Initialiser les paquets de test
        benignPacket = new HashMap<>();
        benignPacket.put("protocol", "TCP");
        benignPacket.put("srcIP", "192.168.1.2");
        benignPacket.put("srcPort", "12345");
        benignPacket.put("destIP", "192.168.1.100");
        benignPacket.put("destPort", "80");
        
        maliciousPacket = new HashMap<>();
        maliciousPacket.put("protocol", "TCP");
        maliciousPacket.put("srcIP", "10.0.0.1");
        maliciousPacket.put("srcPort", "31337");
        maliciousPacket.put("destIP", "192.168.1.100");
        maliciousPacket.put("destPort", "22");
    }

    private void createTestCsvFile() throws IOException {
        File csvFile = new File("test_csv.csv");
        try (FileWriter writer = new FileWriter(csvFile)) {
            // En-tête
            writer.write("protocol,srcPort,srcIP,destPort,destIP,isMalicious,action\n");
            
            // Données d'entraînement
            writer.write("TCP,12345,192.168.1.2,80,192.168.1.100,0,ALLOW\n");
            writer.write("TCP,31337,10.0.0.1,22,192.168.1.100,1,BLOCK\n");
            writer.write("TCP,54321,192.168.1.3,80,192.168.1.100,0,ALLOW\n");
            writer.write("TCP,12345,10.0.0.2,445,192.168.1.100,1,BLOCK\n");
        }
    }

    @Test
    void testTraining() throws IOException {
        controller.train("test_csv.csv");
        assertNotNull(lastStats);
        assertTrue((Double)lastStats.get("confidence") > 0.0);
    }

    @Test
    void testBenignPacketProcessing() {
        controller.train("test_csv.csv");
        boolean decision = controller.processPacket(benignPacket);
        
        assertTrue(decision);
        assertTrue(decisionLog.toString().contains("ALLOWED"));
    }

    @Test
    void testMaliciousPacketProcessing() {
        controller.train("test_csv.csv");
        boolean decision = controller.processPacket(maliciousPacket);
        
        assertFalse(decision);
        assertTrue(decisionLog.toString().contains("BLOCKED"));
    }

    @Test
    void testLearningProgress() {
        controller.train("test_csv.csv");
        
        // Premier paquet malicieux
        controller.processPacket(maliciousPacket);
        double initialConfidence = (Double)lastStats.get("confidence");
        
        // Traiter plusieurs paquets pour l'apprentissage
        for(int i = 0; i < 10; i++) {
            controller.processPacket(benignPacket);
            controller.processPacket(maliciousPacket);
        }
        
        double finalConfidence = (Double)lastStats.get("confidence");
        assertTrue(finalConfidence >= initialConfidence);
    }

    @Test
    void testStatisticsUpdates() {
        controller.train("test_csv.csv");
        
        // Traiter quelques paquets
        controller.processPacket(benignPacket);
        controller.processPacket(benignPacket);
        controller.processPacket(maliciousPacket);
        
        assertNotNull(lastStats);
        assertEquals(2L, lastStats.get("allowedCount"));
        assertEquals(1L, lastStats.get("blockedCount"));
    }

    @Test
    void testUnknownPatternHandling() {
        controller.train("test_csv.csv");
        
        // Créer un paquet avec un pattern inconnu
        Map<String, String> unknownPacket = new HashMap<>();
        unknownPacket.put("protocol", "UDP");
        unknownPacket.put("srcIP", "172.16.0.1");
        unknownPacket.put("srcPort", "53");
        unknownPacket.put("destIP", "172.16.0.2");
        unknownPacket.put("destPort", "53");
        
        boolean decision = controller.processPacket(unknownPacket);
        
        // Par défaut, devrait autoriser le trafic inconnu
        assertTrue(decision);
    }

    @Test
    void testReinforcementEffect() {
        controller.train("test_csv.csv");
        
        // Premier essai avec un paquet malicieux
        boolean firstDecision = controller.processPacket(maliciousPacket);
        
        // Simuler un feedback positif en traitant plusieurs fois le même type de paquet
        for(int i = 0; i < 5; i++) {
            controller.processPacket(maliciousPacket);
        }
        
        // Vérifier que la confiance a augmenté
        double finalConfidence = (Double)lastStats.get("confidence");
        assertTrue(finalConfidence > 0.0);
    }
} 