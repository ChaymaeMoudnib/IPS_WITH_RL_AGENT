package com.example;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import com.example.detection.RuleEngine;
import com.example.gui.Gui;
import com.example.util.RuleLoader;
import java.util.Map;
import java.util.HashMap;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import javax.swing.SwingUtilities;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class IntegrationTest {
    private RuleEngine ruleEngine;
    private Gui gui;
    private Map<String, String> testPacket;
    private CountDownLatch guiLatch;
    private RuleLoader ruleLoader;

    @BeforeEach
    void setUp() throws IOException, InterruptedException {
        // Create necessary files
        createTestFiles();
        
        // Initialize components
        ruleLoader = new RuleLoader();
        ruleEngine = new RuleEngine();
        guiLatch = new CountDownLatch(1);
        
        // Initialize GUI in EDT
        SwingUtilities.invokeLater(() -> {
            gui = new Gui();
            gui.setRuleEngine(ruleEngine);
            guiLatch.countDown();
        });
        
        // Wait for GUI initialization
        if (!guiLatch.await(5, TimeUnit.SECONDS)) {
            throw new RuntimeException("Timeout waiting for GUI initialization");
        }
        
        // Prepare test packet
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
        // Clean up test files
        new File("test_rules.txt").delete();
        
        // Close GUI
        if (gui != null) {
            SwingUtilities.invokeLater(() -> gui.dispose());
        }
    }

    private void createTestFiles() throws IOException {
        // Create rules file
        try (FileWriter writer = new FileWriter("test_rules.txt")) {
            writer.write("TCP any any -> any 80 (msg:Web attack detected; content:admin; severity:HIGH)\n");
            writer.write("TCP any any -> any 22 (msg:SSH attack detected; flags:S; threshold:type both, count 5, seconds 60; severity:CRITICAL)\n");
        }
    }

    @Test
    void testRuleEngine() throws Exception {
        // 1. Verify system initialization
        assertNotNull(ruleEngine);
        assertNotNull(gui);

        // 2. Test rule loading
        ruleEngine.setRules(ruleLoader.getRules());
        assertTrue(ruleEngine.getRules().size() > 0);

        // 3. Test packet matching
        boolean ruleMatch = ruleEngine.matches(testPacket);
        assertTrue(ruleMatch, "Packet should trigger a rule");
        
        // 4. Verify alert generation
        assertNotNull(ruleEngine.getLastAlert());
        assertEquals("Web attack detected", ruleEngine.getLastAlert().getMessage());
    }

    @Test
    void testGuiUpdates() throws Exception {
        // Prepare latch for synchronization
        CountDownLatch updateLatch = new CountDownLatch(1);
        
        // Simulate interface update
        SwingUtilities.invokeLater(() -> {
            gui.getPacketDisplayPanel().appendPacket(testPacket);
            updateLatch.countDown();
        });
        
        // Wait for update
        boolean updated = updateLatch.await(5, TimeUnit.SECONDS);
        assertTrue(updated, "Interface update should be completed");
    }

    @Test
    void testErrorHandling() {
        // 1. Test with invalid packet
        Map<String, String> invalidPacket = new HashMap<>();
        invalidPacket.put("protocol", "INVALID");
        
        // System should handle invalid packets gracefully
        boolean match = ruleEngine.matches(invalidPacket);
        assertFalse(match, "Invalid packets should not match any rules");
    }
} 