package com.example.rl;

import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

public class Environment {

    public State extractState(Packet packet) {
        IpPacket ipPacket = packet.get(IpPacket.class);
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        UdpPacket udpPacket = packet.get(UdpPacket.class);

        String protocol = tcpPacket != null ? "TCP" : (udpPacket != null ? "UDP" : "UNKNOWN");
        String srcPort = String.valueOf(tcpPacket != null ? tcpPacket.getHeader().getSrcPort().valueAsInt() :
                                      (udpPacket != null ? udpPacket.getHeader().getSrcPort().valueAsInt() : 0));
        String destPort = String.valueOf(tcpPacket != null ? tcpPacket.getHeader().getDstPort().valueAsInt() :
                                       (udpPacket != null ? udpPacket.getHeader().getDstPort().valueAsInt() : 0));
        String srcIP = ipPacket != null ? ipPacket.getHeader().getSrcAddr().getHostAddress() : "0.0.0.0";
        String destIP = ipPacket != null ? ipPacket.getHeader().getDstAddr().getHostAddress() : "0.0.0.0";

        return new State(protocol, srcPort, srcIP, destPort, destIP);
    }

    public boolean isMalicious(Packet packet) {
        int dstPort = extractDstPort(packet);
        String payload = packet.toString().toLowerCase();

        boolean suspiciousPort = dstPort == 23 || dstPort == 21  ||dstPort == 49929 || dstPort == 49925 || dstPort == 4444 || dstPort == 31337 || dstPort == 135 || dstPort == 445;
//        boolean suspiciousContent = payload.contains("nmap") || payload.contains("exploit") || payload.contains("telnet");

//        return suspiciousPort || suspiciousContent;
        return suspiciousPort;
    }

    public int extractDstPort(Packet packet) {
        if (packet.contains(TcpPacket.class)) {
            return packet.get(TcpPacket.class).getHeader().getDstPort().valueAsInt();
        } else if (packet.contains(UdpPacket.class)) {
            return packet.get(UdpPacket.class).getHeader().getDstPort().valueAsInt();
        }
        return -1; // Unknown or unsupported protocol
    }

    public int evaluate(Action action, boolean isMalicious) {
        if (!action.isAllowed() && isMalicious) return +1;    // good block
        if (!action.isAllowed() && !isMalicious) return -1;   // false positive
        if (action.isAllowed() && isMalicious) return -10;    // dangerous
        return 0; // allowed good traffic
    }

    public void executeAction(Action action) {
        // Only needed for runtime, not training
    }
}

