package com.example.util;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.util.Map;

public class PacketParserTest {
    
    private static final String VALID_TCP_PACKET = 
        "[Ethernet Header (14 bytes)]\n" +
        "  Destination address: 00:11:22:33:44:55\n" +
        "  Source address: aa:bb:cc:dd:ee:ff\n" +
        "  Type: 0x0800 (IPv4)\n" +
        "[IPv4 Header (20 bytes)]\n" +
        "  Version: 4\n" +
        "  Source address: 192.168.1.1\n" +
        "  Destination address: 192.168.1.2\n" +
        "[TCP Header (32 bytes)]\n" +
        "  Source port: 12345\n" +
        "  Destination port: 80 (HTTP)\n" +
        "  Hex stream: 474554202f20485454502f312e310d0a";

    private static final String VALID_HTTP_PACKET = 
        "[Ethernet Header (14 bytes)]\n" +
        "  Destination address: 00:11:22:33:44:55\n" +
        "  Source address: aa:bb:cc:dd:ee:ff\n" +
        "  Type: 0x0800 (IPv4)\n" +
        "[IPv4 Header (20 bytes)]\n" +
        "  Version: 4\n" +
        "  Source address: 192.168.1.1\n" +
        "  Destination address: 192.168.1.2\n" +
        "[TCP Header (32 bytes)]\n" +
        "  Source port: 12345\n" +
        "  Destination port: 80\n" +
        "  Hex stream: 474554202f20485454502f312e310d0a486f73743a206578616d706c652e636f6d";

    @Test
    public void testValidTcpPacket() {
        Map<String, String> result = PacketParser.parsePacket(VALID_TCP_PACKET);
        assertNotNull(result, "Should parse valid TCP packet");
        assertEquals(result.get("protocol"), "TCP");
        assertEquals(result.get("srcIp"), "192.168.1.1");
        assertEquals(result.get("dstIp"), "192.168.1.2");
        assertEquals(result.get("srcPort"), "12345");
        assertEquals(result.get("dstPort"), "80");
        assertEquals(result.get("dstMac"), "00:11:22:33:44:55");
        assertEquals(result.get("srcMac"), "aa:bb:cc:dd:ee:ff");
    }

    @Test
    public void testHttpDetection() {
        Map<String, String> result = PacketParser.parsePacket(VALID_HTTP_PACKET);
        assertNotNull(result, "Should parse valid HTTP packet");
        assertEquals(result.get("isHttp"), "true");
        assertNotNull(result.get("data"), "Should contain HTTP data");
    }

    @Test
    public void testNullPacket() {
        Map<String, String> result = PacketParser.parsePacket(null);
        assertNull(result, "Should return null for null packet");
    }

    @Test
    public void testEmptyPacket() {
        Map<String, String> result = PacketParser.parsePacket("");
        assertNull(result, "Should return null for empty packet");
    }

    @Test
    public void testInvalidPacket() {
        String invalidPacket = "Invalid packet data";
        Map<String, String> result = PacketParser.parsePacket(invalidPacket);
        assertNull(result, "Should return null for invalid packet");
    }

    @Test
    public void testInvalidMacAddress() {
        String packetWithInvalidMac = 
            "[Ethernet Header (14 bytes)]\n" +
            "  Destination address: invalid:mac:address\n" +
            "  Source address: aa:bb:cc:dd:ee:ff\n" +
            "  Type: 0x0800 (IPv4)\n" +
            "[IPv4 Header (20 bytes)]\n" +
            "  Version: 4\n" +
            "  Source address: 192.168.1.1\n" +
            "  Destination address: 192.168.1.2\n" +
            "[TCP Header (32 bytes)]\n" +
            "  Source port: 12345\n" +
            "  Destination port: 80";
        
        Map<String, String> result = PacketParser.parsePacket(packetWithInvalidMac);
        assertNotNull(result, "Should still parse packet with invalid MAC");
        assertNull(result.get("dstMac"), "Invalid MAC should be null");
    }

    @Test
    public void testInvalidIpAddress() {
        String packetWithInvalidIp = 
            "[Ethernet Header (14 bytes)]\n" +
            "  Destination address: 00:11:22:33:44:55\n" +
            "  Source address: aa:bb:cc:dd:ee:ff\n" +
            "  Type: 0x0800 (IPv4)\n" +
            "[IPv4 Header (20 bytes)]\n" +
            "  Version: 4\n" +
            "  Source address: 256.256.256.256\n" +
            "  Destination address: 192.168.1.2\n" +
            "[TCP Header (32 bytes)]\n" +
            "  Source port: 12345\n" +
            "  Destination port: 80";
        
        Map<String, String> result = PacketParser.parsePacket(packetWithInvalidIp);
        assertNull(result, "Should return null for packet with invalid IP");
    }
} 