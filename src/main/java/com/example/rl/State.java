package com.example.rl;

import org.pcap4j.packet.Packet;
import java.io.Serializable;
import java.util.Objects;

public class State implements Serializable {
    private static final long serialVersionUID = 1L;
    private final String protocol;
    private final String srcPort;
    private final String srcIP;
    private final String destPort;
    private final String destIP;
    private String data;
    
    public State(String protocol, String srcPort, String srcIP, String destPort, String destIP) {
        this.protocol = protocol;
        this.srcPort = srcPort;
        this.srcIP = srcIP;
        this.destPort = destPort;
        this.destIP = destIP;
    }
    
    public String getProtocol() { return protocol; }
    public String getSrcPort() { return srcPort; }
    public String getSrcIP() { return srcIP; }
    public String getDestPort() { return destPort; }
    public String getDestIP() { return destIP; }
    
    public String getData() {
        return data;
    }
    
    @Override
    public int hashCode() {
        return (protocol + srcPort + srcIP + destPort + destIP).hashCode();
    }
    
    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof State)) return false;
        State other = (State) obj;
        return protocol.equals(other.protocol) &&
               srcPort.equals(other.srcPort) &&
               srcIP.equals(other.srcIP) &&
               destPort.equals(other.destPort) &&
               destIP.equals(other.destIP);
    }
    
    @Override
    public String toString() {
        return String.format("%s:%s->%s:%s (%s)", 
            srcIP, srcPort, destIP, destPort, protocol);
    }
}

