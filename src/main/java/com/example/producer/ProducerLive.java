package com.example.producer;

import com.example.util.LivePacketReader;
import com.example.util.PacketParser;
import com.example.designpatterns.StrategyPattern.ProducerStrategy;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.Map;

public class ProducerLive implements ProducerStrategy {
    private final LivePacketReader packetReader;
    private final BlockingQueue<Map<String, String>> packetQueue;
    private volatile boolean running;

    public ProducerLive(String networkInterface) throws Exception {
        this.packetReader = new LivePacketReader(networkInterface);
        this.packetQueue = new LinkedBlockingQueue<>(1000); // Buffer de 1000 paquets
        this.running = true;
    }

    @Override
    public void start(BlockingQueue<String> queue) {
        try {
            while (running) {
                var packet = packetReader.getNextPacket();
                if (packet != null) {
                    // Convertir le paquet en Map et l'ajouter à la queue
                    Map<String, String> packetData = PacketParser.parsePacket(packet.toString());
                    if (packetData != null) {
                        queue.put(packetData.toString());
                    }
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void stop() {
        running = false;
        packetReader.close();
    }
} 