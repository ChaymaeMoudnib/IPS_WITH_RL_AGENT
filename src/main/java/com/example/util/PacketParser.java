package com.example.util;

import java.util.Map;
import java.util.HashMap;
import java.util.regex.Pattern;

public class PacketParser {
    private static final int MINIMUM_FIELDS = 3; // Minimum fields needed for basic packet info
    private static final Pattern HTTP_PORT_PATTERN = Pattern.compile("(80|443|8080|8443)");
    private static final Pattern IP_PATTERN = Pattern.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$");
    private static final Pattern MAC_PATTERN = Pattern.compile("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");

    /**
     * Extracts and validates packet fields from the raw packet string
     * @param packet Raw packet string
     * @return Array of extracted fields or null if invalid
     */
    public static String[] extractPacketFields(String packet) {
        if (packet == null || packet.trim().isEmpty()) {
            return null;
        }

        String[] fields = packet.split("\\n");
        if (fields.length < MINIMUM_FIELDS) {
            return null;
        }

        String[] extractedData = new String[8];
        try {
            // Extract MAC addresses with validation
            if (fields.length > 1 && fields[1].contains("Destination address:")) {
                String mac = fields[1].substring(fields[1].indexOf(":") + 2).trim();
                if (isValidMac(mac)) {
                    extractedData[5] = mac;
                }
            }
            if (fields.length > 2 && fields[2].contains("Source address:")) {
                String mac = fields[2].substring(fields[2].indexOf(":") + 2).trim();
                if (isValidMac(mac)) {
                    extractedData[6] = mac;
                }
            }

            // Extract other fields
            for (String field : fields) {
                if (field.contains("Destination port:")) {
                    int index = field.indexOf(":");
                    extractedData[4] = field.substring(index + 2).trim();
                } else if (field.contains("Source port:")) {
                    int index = field.indexOf(":");
                    extractedData[2] = field.substring(index + 2).trim();
                } else if (field.contains("TCP")) {
                    extractedData[0] = "TCP";
                } else if (field.contains("UDP")) {
                    extractedData[0] = "UDP";
                } else if (field.contains("Destination address:")) {
                    int index = field.indexOf(":");
                    String ip = field.substring(index + 3).trim();
                    if (isValidIp(ip)) {
                        extractedData[3] = ip;
                    }
                } else if (field.contains("Source address:")) {
                    int index = field.indexOf(":");
                    String ip = field.substring(index + 3).trim();
                    if (isValidIp(ip)) {
                        extractedData[1] = ip;
                    }
                } else if (field.contains("Hex stream:")) {
                    int index = field.indexOf(":");
                    String hexStream = field.substring(index + 1).replaceAll(" ", "");
                    if (isValidHex(hexStream)) {
                        extractedData[7] = HexToAscii.hexToAscii(hexStream);
                    }
                }
            }

            // Validate required fields
            if (!isValidPacket(extractedData)) {
                return null;
            }

            return extractedData;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Parses a packet string into a structured map of packet data
     * @param packet Raw packet string
     * @return Map containing parsed packet data or null if invalid
     */
    public static Map<String, String> parsePacket(String packet) {
        if (packet == null) {
            return null;
        }

        String[] extractedData = extractPacketFields(packet);
        if (extractedData == null) {
            return null;
        }

        Map<String, String> packetData = new HashMap<>();
        
        // Détection du protocole de base
        String baseProtocol = extractedData[0];
        String srcPort = extractedData[2];
        String destPort = extractedData[4];
        String data = extractedData[7];

        // Détection HTTP/HTTPS
        if ("TCP".equals(baseProtocol)) {
            if (isHttpTraffic(srcPort, destPort, data)) {
                packetData.put("protocol", "HTTP");
            } else if (isHttpsTraffic(srcPort, destPort, data)) {
                packetData.put("protocol", "HTTPS");
            } else {
                packetData.put("protocol", "TCP");
            }
        } else {
            packetData.put("protocol", baseProtocol);
        }

        // Autres champs
        packetData.put("srcIP", extractedData[1]);
        packetData.put("srcPort", srcPort);
        packetData.put("destIP", extractedData[3]);
        packetData.put("destPort", destPort);

        // Extraire les flags TCP si présents
        if ("TCP".equals(baseProtocol)) {
            String flags = extractTcpFlags(packet);
            if (flags != null) {
                packetData.put("flags", flags);
            }
        }

        // Ajouter le contenu du paquet
        if (data != null) {
            packetData.put("data", data);
        }

        return packetData;
    }

    private static String extractTcpFlags(String packet) {
        StringBuilder flags = new StringBuilder();
        
        if (packet.contains("SYN")) flags.append("S");
        if (packet.contains("ACK")) flags.append("A");
        if (packet.contains("FIN")) flags.append("F");
        if (packet.contains("RST")) flags.append("R");
        if (packet.contains("PSH")) flags.append("P");
        if (packet.contains("URG")) flags.append("U");
        
        return flags.length() > 0 ? flags.toString() : null;
    }

    /**
     * Validates if the packet contains HTTP traffic
     */
    private static boolean isHttpTraffic(String srcPort, String destPort, String data) {
        // Vérifier les ports HTTP standards
        if ("80".equals(srcPort) || "80".equals(destPort) || 
            "8080".equals(srcPort) || "8080".equals(destPort)) {
            return true;
        }

        // Vérifier le contenu pour les signatures HTTP
        if (data != null) {
            String upperData = data.toUpperCase();
            
            // En-têtes spécifiques à Chrome
            boolean isChrome = upperData.contains("CHROME/") ||
                             upperData.contains("CHROMIUM/") ||
                             upperData.contains("MOZILLA/5.0") ||
                             upperData.contains("WEBKIT");
            
            // Méthodes HTTP communes
            boolean hasHttpMethod = upperData.contains("GET /") || 
                                  upperData.contains("POST /") || 
                                  upperData.contains("HEAD /") ||
                                  upperData.contains("PUT /") ||
                                  upperData.contains("DELETE /") ||
                                  upperData.contains("OPTIONS /") ||
                                  upperData.contains("CONNECT /") ||
                                  upperData.contains("TRACE /") ||
                                  upperData.contains("PATCH /");
            
            // En-têtes HTTP communs
            boolean hasHttpHeader = upperData.contains("HOST: ") ||
                                  upperData.contains("USER-AGENT: ") ||
                                  upperData.contains("ACCEPT: ") ||
                                  upperData.contains("CONTENT-TYPE: ") ||
                                  upperData.contains("CONTENT-LENGTH: ") ||
                                  upperData.contains("COOKIE: ") ||
                                  upperData.contains("REFERER: ") ||
                                  upperData.contains("SEC-CH-UA") || // En-tête Chrome
                                  upperData.contains("SEC-CH-UA-MOBILE") || // En-tête Chrome
                                  upperData.contains("SEC-CH-UA-PLATFORM"); // En-tête Chrome
            
            // Réponses HTTP
            boolean hasHttpResponse = upperData.contains("HTTP/1.") ||
                                    upperData.contains("HTTP/2") ||
                                    upperData.contains("HTTP/3") ||
                                    upperData.contains("200 OK") ||
                                    upperData.contains("404 NOT FOUND") ||
                                    upperData.contains("500 INTERNAL") ||
                                    upperData.contains("301 MOVED") ||
                                    upperData.contains("302 FOUND");
            
            return isChrome || hasHttpMethod || hasHttpHeader || hasHttpResponse;
        }
        return false;
    }

    private static boolean isHttpsTraffic(String srcPort, String destPort, String data) {
        // Vérifier les ports HTTPS standards
        if ("443".equals(srcPort) || "443".equals(destPort) || 
            "8443".equals(srcPort) || "8443".equals(destPort)) {
            return true;
        }

        // Vérifier les signatures TLS/SSL dans les données
        if (data != null) {
            String hexData = data.replaceAll(" ", "").toUpperCase();
            
            // 1. Handshake TLS/SSL
            boolean isTlsHandshake = hexData.contains("160301") || // TLS 1.0
                                   hexData.contains("160302") || // TLS 1.1
                                   hexData.contains("160303") || // TLS 1.2
                                   hexData.contains("160304");   // TLS 1.3
            
            // 2. Signatures de Chrome
            boolean isChrome = data.toUpperCase().contains("CHROME") ||
                             hexData.contains("43484F4D45") || // "CHROME" en hex
                             hexData.contains("474F4F474C45") || // "GOOGLE" en hex
                             data.toUpperCase().contains("MOZILLA/5.0") ||
                             hexData.contains("4D4F5A494C4C412F352E30"); // "MOZILLA/5.0" en hex
            
            // 3. Certificats et échanges de clés
            boolean isCertOrKey = hexData.contains("0B") || // Certificate
                                hexData.contains("0C") || // Server Key Exchange
                                hexData.contains("0F") || // Certificate Request
                                hexData.contains("10");   // Client Key Exchange
            
            // 4. Application Data TLS
            boolean isAppData = hexData.contains("170303") || // Application Data TLS 1.2
                              hexData.contains("170304");   // Application Data TLS 1.3
            
            // 5. ALPN (Application Layer Protocol Negotiation)
            boolean isAlpn = hexData.contains("0010") && // ALPN Extension
                           (hexData.contains("68322") || // "h2"
                            hexData.contains("0103") ||  // Protocol List
                            hexData.contains("7374732") || // "sts"
                            hexData.contains("687474702F312E31")); // "http/1.1"
            
            // 6. SNI (Server Name Indication)
            boolean isSni = hexData.contains("0000") && // SNI Extension
                          hexData.length() > 40;  // SNI typically has significant length
            
            // 7. Chrome QUIC support
            boolean hasQuic = hexData.contains("51554943") || // "QUIC"
                            data.toUpperCase().contains("QUIC");
            
            return isTlsHandshake || isChrome || isCertOrKey || isAppData || isAlpn || isSni || hasQuic;
        }
        return false;
    }

    /**
     * Validates if the packet has all required fields
     */
    private static boolean isValidPacket(String[] packetData) {
        return packetData[0] != null && // Protocol
               packetData[1] != null && // Source IP
               packetData[3] != null;   // Destination IP
    }

    /**
     * Validates an IP address format
     */
    private static boolean isValidIp(String ip) {
        return ip != null && IP_PATTERN.matcher(ip).matches();
    }

    /**
     * Validates a MAC address format
     */
    private static boolean isValidMac(String mac) {
        return mac != null && MAC_PATTERN.matcher(mac).matches();
    }

    /**
     * Validates a hex string format
     */
    private static boolean isValidHex(String hex) {
        return hex != null && hex.matches("^[0-9A-Fa-f]+$");
    }
}
