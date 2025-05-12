package com.example.rl;

import com.example.util.PacketReader;
import com.example.util.PacketReaderFactory;
import com.example.detection.RuleEngine;
import org.pcap4j.packet.Packet;

import javax.swing.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.List;

public class Trainer {

    private static int totalReward = 0;
    private static volatile boolean stopTraining = false; // Flag to stop the training loop
    private static TrainerGUI gui;
    
    // Performance metrics
    private static int truePositives = 0;
    private static int falsePositives = 0;
    private static int trueNegatives = 0;
    private static int falseNegatives = 0;
    private static List<Double> accuracyHistory = new ArrayList<>();
    private static List<Double> precisionHistory = new ArrayList<>();
    private static List<Double> recallHistory = new ArrayList<>();
    private static List<Double> f1ScoreHistory = new ArrayList<>();

    public static void main(String[] args) {
        // Set up the GUI
        gui = new TrainerGUI();

        // Create and start the training process
        startTraining();
    }

    public static void startTraining() {
        FileWriter fw = null;

        try {
            PacketReader reader = PacketReaderFactory.createPacketReader("offline", "train.pcapng");
            Environment env = new Environment();
            RLAgent agent = new RLAgent();
            RuleEngine ruleEngine = new RuleEngine();

            // Try to load existing model if available
            File modelFile = new File("trained_model.rl");
            if (modelFile.exists()) {
                try {
                    agent.loadModel("trained_model.rl");
                    gui.updateTextPane("Loaded existing model from trained_model.rl\n", false);
                } catch (Exception e) {
                    gui.updateTextPane("Could not load existing model, starting fresh: " + e.getMessage() + "\n", false);
                }
            }

            // Write CSV header if file doesn't exist
            File csvFile = new File("features1.csv");
            boolean headerExists = csvFile.exists();
            fw = new FileWriter(csvFile, true);

            if (!headerExists) {
                fw.write("protocol,srcPort,srcIP,destPort,destIP,isMalicious,action,ruleMatch,ruleSeverity\n");
            }

            Packet packet;
            int packetCount = 0;
            while ((packet = reader.getNextPacket()) != null && !stopTraining) {
                packetCount++;
                
                // Extract features
                State state = env.extractState(packet);
                
                // Convert packet to Map for RuleEngine
                Map<String, String> packetData = new HashMap<>();
                packetData.put("protocol", state.getProtocol());
                packetData.put("srcPort", state.getSrcPort());
                packetData.put("srcIP", state.getSrcIP());
                packetData.put("destPort", state.getDestPort());
                packetData.put("destIP", state.getDestIP());
                
                // Get rule match and severity
                boolean ruleMatch = ruleEngine.matches(packetData);
                String ruleSeverity = ruleEngine.getLastMatchedRule() != null ? 
                    ruleEngine.getLastMatchedRule().getOptions().getOrDefault("severity", "medium") : "none";
                
                // If rule matches, consider it malicious
                boolean isMalicious = ruleMatch || env.isMalicious(packet);
                
                // Get RL action
                Action rlAction = agent.getAction(state);
                
                // If rule matches, force block action and provide strong negative reward
                if (ruleMatch) {
                    rlAction = new Action(false, 1.0); // Force block with high confidence
                    int negativeReward = -10; // Strong negative reward for not blocking
                    agent.updateQValue(state, true, negativeReward); // Update Q-value to discourage allowing
                }
                
                // Update performance metrics
                updateMetrics(rlAction.isAllowed(), ruleMatch, isMalicious);
                
                // Calculate and display metrics every 100 packets
                if (packetCount % 100 == 0) {
                    displayMetrics();
                }

                String output = String.format("Packet: %s\nRL Decision: %s\nRule Match: %b (Severity: %s)\nMalicious: %b\n",
                    state, rlAction, ruleMatch, ruleSeverity, isMalicious);
                gui.updateTextPane(output, isMalicious);

                // Calculate reward based on both rule match and RL decision
                int reward = calculateReward(rlAction.isAllowed(), ruleMatch, isMalicious, ruleSeverity);
                totalReward += reward;

                // Update RL agent with the reward
                agent.updateQValue(state, rlAction.isAllowed(), reward);

                // Write data to CSV
                fw.write(String.format("%s,%s,%s,%s,%s,%b,%b,%b,%s\n",
                    state.getProtocol(),
                    state.getSrcPort(),
                    state.getSrcIP(),
                    state.getDestPort(),
                    state.getDestIP(),
                    isMalicious,
                    rlAction.isAllowed(),
                    ruleMatch,
                    ruleSeverity));

                // Also output state to GUI
                gui.updateTextPane("Extracted state: " + state + "\n", isMalicious);

                // Simulate a short delay to make training less intense (for testing)
                Thread.sleep(100);
            }

            reader.close();
            displayFinalMetrics();
            
            // Save the trained model
            try {
                agent.saveModel("trained_model.rl");
                gui.updateTextPane("Model saved successfully to trained_model.rl\n", false);
            } catch (Exception e) {
                gui.updateTextPane("Error saving model: " + e.getMessage() + "\n", false);
            }

            gui.updateTextPane("Training finished. Total reward: " + totalReward + "\n", false);

        } catch (IOException | RuntimeException | InterruptedException e) {
            e.printStackTrace();
            gui.updateTextPane("Error: " + e.getMessage() + "\n", false);
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            try {
                if (fw != null) fw.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static int calculateReward(boolean rlAllowed, boolean ruleMatch, boolean isMalicious, String ruleSeverity) {
        // Base reward calculation
        int reward = 0;
        
        // If rule matches, strongly encourage blocking
        if (ruleMatch) {
            if (!rlAllowed) {
                // Good: Blocked when rule matches
                reward = 10;
            } else {
                // Bad: Allowed when rule matches
                reward = -20;
            }
        } else {
            // Normal reward calculation for non-rule matches
            if (isMalicious) {
                reward = !rlAllowed ? 5 : -10; // Reward blocking malicious, penalize allowing
            } else {
                reward = rlAllowed ? 1 : -5; // Small reward for allowing normal traffic, penalty for blocking
            }
        }
        
        // Adjust reward based on rule severity
        if (ruleMatch) {
            switch (ruleSeverity.toLowerCase()) {
                case "high":
                    reward *= 2;
                    break;
                case "medium":
                    reward *= 1.5;
                    break;
                case "low":
                    reward *= 1.2;
                    break;
            }
        }
        
        return reward;
    }

    private static void updateMetrics(boolean rlAllowed, boolean ruleMatch, boolean isMalicious) {
        if (isMalicious) {
            if (!rlAllowed) truePositives++;
            else falseNegatives++;
        } else {
            if (rlAllowed) trueNegatives++;
            else falsePositives++;
        }
    }

    private static void displayMetrics() {
        double accuracy = calculateAccuracy();
        double precision = calculatePrecision();
        double recall = calculateRecall();
        double f1Score = calculateF1Score(precision, recall);

        accuracyHistory.add(accuracy);
        precisionHistory.add(precision);
        recallHistory.add(recall);
        f1ScoreHistory.add(f1Score);

        String metrics = String.format("\nPerformance Metrics:\n" +
            "Accuracy: %.2f%%\n" +
            "Precision: %.2f%%\n" +
            "Recall: %.2f%%\n" +
            "F1 Score: %.2f%%\n" +
            "True Positives: %d\n" +
            "False Positives: %d\n" +
            "True Negatives: %d\n" +
            "False Negatives: %d\n",
            accuracy, precision, recall, f1Score,
            truePositives, falsePositives, trueNegatives, falseNegatives);

        gui.updateTextPane(metrics, false);
    }

    private static void displayFinalMetrics() {
        double avgAccuracy = accuracyHistory.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        double avgPrecision = precisionHistory.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        double avgRecall = recallHistory.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        double avgF1Score = f1ScoreHistory.stream().mapToDouble(Double::doubleValue).average().orElse(0);

        String finalMetrics = String.format("\nFinal Performance Metrics:\n" +
            "Average Accuracy: %.2f%%\n" +
            "Average Precision: %.2f%%\n" +
            "Average Recall: %.2f%%\n" +
            "Average F1 Score: %.2f%%\n",
            avgAccuracy, avgPrecision, avgRecall, avgF1Score);

        gui.updateTextPane(finalMetrics, false);
    }

    private static double calculateAccuracy() {
        int total = truePositives + falsePositives + trueNegatives + falseNegatives;
        return total > 0 ? (double)(truePositives + trueNegatives) / total * 100 : 0;
    }

    private static double calculatePrecision() {
        int totalPositives = truePositives + falsePositives;
        return totalPositives > 0 ? (double)truePositives / totalPositives * 100 : 0;
    }

    private static double calculateRecall() {
        int totalActualPositives = truePositives + falseNegatives;
        return totalActualPositives > 0 ? (double)truePositives / totalActualPositives * 100 : 0;
    }

    private static double calculateF1Score(double precision, double recall) {
        return (precision + recall > 0) ? 2 * (precision * recall) / (precision + recall) : 0;
    }

    public static void stopTraining() {
        stopTraining = true;
    }

    public static void continueTraining() {
        stopTraining = false;
        totalReward = 0;
        resetMetrics();
        gui.updateTextPane("Continuing training...\n", false);
        startTraining();
    }

    private static void resetMetrics() {
        truePositives = 0;
        falsePositives = 0;
        trueNegatives = 0;
        falseNegatives = 0;
        accuracyHistory.clear();
        precisionHistory.clear();
        recallHistory.clear();
        f1ScoreHistory.clear();
    }
}
