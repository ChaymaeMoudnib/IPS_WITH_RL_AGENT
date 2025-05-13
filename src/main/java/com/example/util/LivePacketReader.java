package com.example.util;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import java.util.logging.Logger;
import java.util.logging.Level;

public class LivePacketReader implements PacketReader {
    private static final Logger LOGGER = Logger.getLogger(LivePacketReader.class.getName());
    private PcapHandle handle;
    private String networkInterface;

    public LivePacketReader(String networkInterface) throws Exception {
        this.networkInterface = networkInterface;
        try {
            PcapNetworkInterface nif = Pcaps.getDevByName(networkInterface);
            if (nif == null) {
                throw new IllegalArgumentException("Network interface not found: " + networkInterface);
            }
            this.handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 1000); // Increased timeout to 1 second
            LOGGER.info("Successfully opened network interface: " + networkInterface);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error opening network interface: " + networkInterface, e);
            throw e;
        }
    }

    @Override
    public Packet getNextPacket() {
        try {
            return handle.getNextPacket();
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error reading packet", e);
            return null;
        }
    }

    @Override
    public void close() {
        if (handle != null) {
            try {
                handle.close();
                LOGGER.info("Closed network interface: " + networkInterface);
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Error closing network interface", e);
            }
        }
    }
}

