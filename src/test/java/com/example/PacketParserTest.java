package com.example;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import com.example.util.PacketParser;
import java.util.Map;

public class PacketParserTest {
    private String sampleTcpPacket;
    private String sampleHttpPacket;
    private String sampleHttpsPacket;
    
    @BeforeEach
    void setUp() {
        // Simuler un paquet TCP
        sampleTcpPacket = "TCP Packet\n" +
            "Destination address: 192.168.1.100\n" +
            "Source address: 192.168.1.1\n" +
            "Source port: 54321\n" +
            "Destination port: 80\n" +
            "Flags: SYN ACK\n" +
            "Hex stream: 474554202F20485454502F312E310D0A";

        // Simuler un paquet HTTP
        sampleHttpPacket = "TCP Packet\n" +
            "Destination address: 192.168.1.100\n" +
            "Source address: 192.168.1.1\n" +
            "Source port: 54321\n" +
            "Destination port: 80\n" +
            "Hex stream: 474554202F20485454502F312E310D0A486F73743A206578616D706C652E636F6D";

        // Simuler un paquet HTTPS
        sampleHttpsPacket = "TCP Packet\n" +
            "Destination address: 192.168.1.100\n" +
            "Source address: 192.168.1.1\n" +
            "Source port: 54321\n" +
            "Destination port: 443\n" +
            "Hex stream: 160303010200010001FC0303";
    }

    @Test
    void testParseValidTcpPacket() {
        Map<String, String> packetData = PacketParser.parsePacket(sampleTcpPacket);
        
        assertNotNull(packetData);
        assertEquals("TCP", packetData.get("protocol"));
        assertEquals("192.168.1.1", packetData.get("srcIP"));
        assertEquals("54321", packetData.get("srcPort"));
        assertEquals("192.168.1.100", packetData.get("destIP"));
        assertEquals("80", packetData.get("destPort"));
        assertEquals("SA", packetData.get("flags"));
    }

    @Test
    void testParseHttpPacket() {
        Map<String, String> packetData = PacketParser.parsePacket(sampleHttpPacket);
        
        assertNotNull(packetData);
        assertEquals("HTTP", packetData.get("protocol"));
        assertEquals("80", packetData.get("destPort"));
        assertTrue(packetData.get("data").contains("GET"));
    }

    @Test
    void testParseHttpsPacket() {
        Map<String, String> packetData = PacketParser.parsePacket(sampleHttpsPacket);
        
        assertNotNull(packetData);
        assertEquals("HTTPS", packetData.get("protocol"));
        assertEquals("443", packetData.get("destPort"));
    }

    @Test
    void testParseInvalidPacket() {
        String invalidPacket = "Invalid\nPacket\nFormat";
        Map<String, String> packetData = PacketParser.parsePacket(invalidPacket);
        
        assertNull(packetData);
    }

    @Test
    void testParseNullPacket() {
        Map<String, String> packetData = PacketParser.parsePacket(null);
        
        assertNull(packetData);
    }

    @Test
    void testExtractTcpFlags() {
        String packetWithFlags = "TCP Packet\n" +
            "Flags: SYN ACK FIN PSH URG RST\n" +
            "Other data...";
        
        Map<String, String> packetData = PacketParser.parsePacket(packetWithFlags);
        assertNotNull(packetData);
        assertEquals("SAFPUR", packetData.get("flags"));
    }
} 