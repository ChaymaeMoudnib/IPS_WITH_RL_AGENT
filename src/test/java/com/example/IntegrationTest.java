package com.example;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import com.example.util.PacketParser;
import com.example.util.RuleEngine;
import com.example.gui.Gui;
import java.util.Map;
import java.util.HashMap;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import javax.swing.SwingUtilities;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class IntegrationTest {
    private IDPSController idpsController;
    private RuleEngine ruleEngine;
    private Gui gui;
    private Map<String, String> testPacket;
    private CountDownLatch guiLatch;

    @BeforeEach
    void setUp() throws IOException, InterruptedException {
        // Créer les fichiers nécessaires
        createTestFiles();
        
        // Initialiser les composants
        idpsController = new IDPSController();
        ruleEngine = new RuleEngine();
        guiLatch = new CountDownLatch(1);
        
        // Initialiser l'interface graphique dans l'EDT
        SwingUtilities.invokeLater(() -> {
            gui = new Gui();
            guiLatch.countDown();
        });
        
        // Attendre que l'interface soit initialisée
        if (!guiLatch.await(5, TimeUnit.SECONDS)) {
            throw new RuntimeException("Timeout waiting for GUI initialization");
        }
        
        // Préparer un paquet de test
        testPacket = new HashMap<>();
        testPacket.put("protocol", "TCP");
        testPacket.put("srcIP", "192.168.1.1");
        testPacket.put("srcPort", "12345");
        testPacket.put("destIP", "192.168.1.100");
        testPacket.put("destPort", "80");
        testPacket.put("data", "GET /admin HTTP/1.1");
    }

    @AfterEach
    void tearDown() {
        // Nettoyer les fichiers de test
        new File("test_csv.csv").delete();
        new File("test_rules.txt").delete();
        
        // Fermer l'interface graphique
        if (gui != null) {
            SwingUtilities.invokeLater(() -> gui.dispose());
        }
    }

    private void createTestFiles() throws IOException {
        // Créer le fichier CSV d'entraînement
        try (FileWriter writer = new FileWriter("test_csv.csv")) {
            writer.write("protocol,srcPort,srcIP,destPort,destIP,isMalicious,action\n");
            writer.write("TCP,12345,192.168.1.1,80,192.168.1.100,0,ALLOW\n");
            writer.write("TCP,31337,10.0.0.1,22,192.168.1.100,1,BLOCK\n");
        }
        
        // Créer le fichier de règles
        try (FileWriter writer = new FileWriter("test_rules.txt")) {
            writer.write("TCP any any -> any 80 (msg:Web attack detected; content:admin; severity:HIGH)\n");
            writer.write("TCP any any -> any 22 (msg:SSH attack detected; flags:S; threshold:type both, count 5, seconds 60; severity:CRITICAL)\n");
        }
    }

    @Test
    void testCompleteWorkflow() throws Exception {
        // 1. Vérifier l'initialisation du système
        assertNotNull(idpsController);
        assertNotNull(ruleEngine);
        assertNotNull(gui);

        // 2. Tester le chargement des règles
        ruleEngine.loadRulesFromFile("test_rules.txt");
        assertEquals(2, ruleEngine.getRuleCount());

        // 3. Tester l'entraînement du RL
        idpsController.train("test_csv.csv");
        
        // 4. Tester la détection de paquets malveillants
        boolean ruleMatch = ruleEngine.matches(testPacket);
        assertTrue(ruleMatch, "Le paquet devrait déclencher une règle");
        
        // 5. Tester la décision du RL
        boolean rlDecision = idpsController.processPacket(testPacket);
        // Le RL devrait bloquer ce paquet car il contient "admin"
        assertFalse(rlDecision, "Le RL devrait bloquer ce paquet");
        
        // 6. Tester la mise à jour des statistiques
        Map<String, Object> stats = idpsController.getStatistics();
        assertNotNull(stats);
        assertTrue((Long)stats.get("blockedCount") > 0);
    }

    @Test
    void testPacketProcessingPipeline() {
        // 1. Parser le paquet
        String rawPacket = "TCP Packet\n" +
            "Destination address: 192.168.1.100\n" +
            "Source address: 192.168.1.1\n" +
            "Source port: 12345\n" +
            "Destination port: 80\n" +
            "Flags: SYN ACK\n" +
            "Hex stream: 474554202F20485454502F312E310D0A";
        
        Map<String, String> parsedPacket = PacketParser.parsePacket(rawPacket);
        assertNotNull(parsedPacket);
        
        // 2. Vérifier les règles
        ruleEngine.loadRulesFromFile("test_rules.txt");
        boolean ruleMatch = ruleEngine.matches(parsedPacket);
        
        // 3. Appliquer la décision RL
        boolean rlDecision = idpsController.processPacket(parsedPacket);
        
        // 4. Vérifier la cohérence des décisions
        if (ruleMatch) {
            assertFalse(rlDecision, "Le paquet correspondant à une règle devrait être bloqué");
        }
    }

    @Test
    void testGuiUpdates() throws Exception {
        // Préparer un latch pour la synchronisation
        CountDownLatch updateLatch = new CountDownLatch(1);
        
        // Simuler la mise à jour de l'interface
        SwingUtilities.invokeLater(() -> {
            gui.updateDisplay(testPacket);
            updateLatch.countDown();
        });
        
        // Attendre la mise à jour
        boolean updated = updateLatch.await(5, TimeUnit.SECONDS);
        assertTrue(updated, "La mise à jour de l'interface devrait être terminée");
        
        // Vérifier que l'interface a été mise à jour
        assertNotNull(gui.getLastDisplayedPacket());
    }

    @Test
    void testErrorHandling() {
        // 1. Tester avec un fichier CSV invalide
        assertThrows(IOException.class, () -> {
            idpsController.train("nonexistent.csv");
        });
        
        // 2. Tester avec un paquet mal formé
        Map<String, String> invalidPacket = new HashMap<>();
        invalidPacket.put("protocol", "INVALID");
        
        // Le système devrait gérer gracieusement les paquets invalides
        boolean decision = idpsController.processPacket(invalidPacket);
        assertTrue(decision, "Les paquets invalides devraient être autorisés par défaut");
        
        // 3. Tester avec des règles invalides
        String invalidRule = "Invalid rule format";
        assertThrows(IllegalArgumentException.class, () -> {
            ruleEngine.addRule(invalidRule);
        });
    }
} 