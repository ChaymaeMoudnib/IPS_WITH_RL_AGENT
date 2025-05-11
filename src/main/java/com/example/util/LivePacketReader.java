package com.example.util;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

public class LivePacketReader implements PacketReader {
    private PcapHandle handle;
    private String networkInterface;

    public LivePacketReader(String networkInterface) throws Exception {
        this.networkInterface = networkInterface;
        this.handle = Pcaps.getDevByName(networkInterface)
            .openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
    }

    @Override
    public Packet getNextPacket() {
        try {
            return handle.getNextPacket();
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public void close() {
        if (handle != null) {
            handle.close();
        }
    }
}

