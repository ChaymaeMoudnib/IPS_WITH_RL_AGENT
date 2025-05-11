package com.example;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import com.example.util.RuleEngine;
import com.example.util.Rule;
import java.util.Map;
import java.util.HashMap;

public class RuleEngineTest {
    private RuleEngine ruleEngine;
    private Map<String, String> packetData;

    @BeforeEach
    void setUp() {
        ruleEngine = new RuleEngine();
        packetData = new HashMap<>();
        packetData.put("protocol", "TCP");
        packetData.put("srcIP", "192.168.1.1");
        packetData.put("srcPort", "12345");
        packetData.put("destIP", "192.168.1.100");
        packetData.put("destPort", "80");
        packetData.put("data", "GET /admin HTTP/1.1");
    }

    @Test
    void testAddValidRule() {
        String ruleString = "TCP any any -> any 80 (msg:Web attack detected; content:admin; severity:HIGH)";
        ruleEngine.addRule(ruleString);
        assertEquals(1, ruleEngine.getRuleCount());
    }

    @Test
    void testAddInvalidRule() {
        String invalidRule = "Invalid rule format";
        try {
            ruleEngine.addRule(invalidRule);
            fail("Should throw IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            // Test réussi
            assertEquals(0, ruleEngine.getRuleCount());
        }
    }

    @Test
    void testMatchSingleRule() {
        ruleEngine.addRule("TCP any any -> any 80 (msg:Web attack detected; content:admin; severity:HIGH)");
        assertTrue(ruleEngine.matches(packetData));
        Rule matchedRule = ruleEngine.getLastMatchedRule();
        assertNotNull(matchedRule);
        assertEquals("HIGH", matchedRule.getOption("severity"));
    }

    @Test
    void testNoMatch() {
        ruleEngine.addRule("TCP any any -> any 443 (msg:HTTPS attack; content:admin; severity:HIGH)");
        assertFalse(ruleEngine.matches(packetData));
        assertNull(ruleEngine.getLastMatchedRule());
    }

    @Test
    void testMultipleRules() {
        ruleEngine.addRule("TCP any any -> any 80 (msg:Web attack; content:admin; severity:HIGH)");
        ruleEngine.addRule("TCP any any -> any 443 (msg:HTTPS attack; content:admin; severity:HIGH)");
        ruleEngine.addRule("UDP any any -> any any (msg:UDP flood; threshold:type both, count 100, seconds 60; severity:MEDIUM)");
        
        assertEquals(3, ruleEngine.getRuleCount());
        assertTrue(ruleEngine.matches(packetData));
    }

    @Test
    void testRuleWithThreshold() {
        ruleEngine.addRule("TCP any any -> any 80 (msg:Brute force; threshold:type both, count 3, seconds 60; severity:HIGH)");
        
        // Premier essai
        assertTrue(ruleEngine.matches(packetData));
        
        // Deuxième essai dans la même fenêtre de temps
        assertTrue(ruleEngine.matches(packetData));
        
        // Troisième essai - devrait déclencher l'alerte
        assertTrue(ruleEngine.matches(packetData));
        
        Rule matchedRule = ruleEngine.getLastMatchedRule();
        assertNotNull(matchedRule);
        assertEquals("HIGH", matchedRule.getOption("severity"));
    }

    @Test
    void testRuleWithFlags() {
        ruleEngine.addRule("TCP any any -> any any (msg:SYN scan; flags:S; severity:HIGH)");
        
        // Ajouter le flag SYN
        packetData.put("flags", "S");
        assertTrue(ruleEngine.matches(packetData));
        
        // Changer pour un autre flag
        packetData.put("flags", "A");
        assertFalse(ruleEngine.matches(packetData));
    }

    @Test
    void testContentMatching() {
        ruleEngine.addRule("TCP any any -> any any (msg:SQL injection; content:UNION SELECT; nocase; severity:CRITICAL)");
        
        // Test avec contenu correspondant
        packetData.put("data", "SELECT * FROM users UNION SELECT password FROM admin");
        assertTrue(ruleEngine.matches(packetData));
        
        // Test avec contenu ne correspondant pas
        packetData.put("data", "SELECT * FROM users");
        assertFalse(ruleEngine.matches(packetData));
    }
} 