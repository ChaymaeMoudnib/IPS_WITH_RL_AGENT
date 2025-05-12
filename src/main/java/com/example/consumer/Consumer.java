package com.example.consumer;

import com.example.detection.AnomalyDetector;
import com.example.detection.Alert;
import com.example.logging.AlertLogger;
import com.example.util.RuleEngine;
import com.example.util.PacketParser;
import com.example.designpatterns.StrategyPattern.ConsumerStrategy;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.io.IOException;

public class Consumer implements ConsumerStrategy {
    private final AnomalyDetector anomalyDetector;
    private final AlertLogger alertLogger;
    private final RuleEngine ruleEngine;
    private volatile boolean running;

    public Consumer() {
        this.anomalyDetector = new AnomalyDetector();
        try {
            this.alertLogger = new AlertLogger();
        } catch (IOException e) {
            throw new RuntimeException("Failed to initialize AlertLogger", e);
        }
        this.ruleEngine = new RuleEngine();
        this.running = true;
    }

    @Override
    public void start(BlockingQueue<String> queue) {
        try {
            while (running) {
                String packetStr = queue.take();
                Map<String, String> packet = PacketParser.parsePacket(packetStr);
                if (packet != null) {
                    processPacket(packet);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void processPacket(Map<String, String> packet) {
        // Vérifier les règles Snort
        if (ruleEngine.matches(packet)) {
            alertLogger.logAlert(ruleEngine.getLastMatchedRule(), packet);
        }

        // Vérifier les anomalies
        Alert anomaly = anomalyDetector.detectAnomaly(packet);
        if (anomaly != null) {
            alertLogger.logAnomaly(anomaly, packet);
        }
    }

    @Override
    public void stop() {
        running = false;
        alertLogger.close();
    }
}
