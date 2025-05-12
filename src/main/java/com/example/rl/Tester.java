package com.example.rl;

import com.example.util.PacketReader;
import com.example.util.PacketReaderFactory;
import com.example.detection.RuleEngine;
import org.pcap4j.packet.Packet;

import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.List;

public class Tester {
    private static int truePositives = 0;
    private static int falsePositives = 0;
    private static int trueNegatives = 0;
    private static int falseNegatives = 0;
    private static List<Double> accuracyHistory = new ArrayList<>();
    private static List<Double> precisionHistory = new ArrayList<>();
    private static List<Double> recallHistory = new ArrayList<>();
    private static List<Double> f1ScoreHistory = new ArrayList<>();

    public static void main(String[] args) {
        try {
            // Load the trained model
            RLAgent agent = new RLAgent();
            try {
                agent.loadModel("trained_model.rl");
                System.out.println("Successfully loaded trained model");
            } catch (Exception e) {
                System.out.println("Error loading model: " + e.getMessage());
                return;
            }

            // Initialize components
            PacketReader reader = PacketReaderFactory.createPacketReader("offline", "test.pcapng");
            Environment env = new Environment();
            RuleEngine ruleEngine = new RuleEngine();

            int packetCount = 0;
            Packet packet;
            while ((packet = reader.getNextPacket()) != null) {
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
                
                // Get decisions
                Action rlAction = agent.getAction(state);
                boolean ruleMatch = ruleEngine.matches(packetData);
                boolean isMalicious = ruleMatch || env.isMalicious(packet);
                
                // Update metrics
                updateMetrics(rlAction.isAllowed(), ruleMatch, isMalicious);
                
                // Display packet details
                System.out.printf("\nPacket %d:\n", packetCount);
                System.out.printf("State: %s\n", state);
                System.out.printf("RL Decision: %s\n", rlAction);
                System.out.printf("Rule Match: %b\n", ruleMatch);
                System.out.printf("Actual: %s\n", isMalicious ? "MALICIOUS" : "NORMAL");
                
                // Display metrics every 100 packets
                if (packetCount % 100 == 0) {
                    displayMetrics();
                }
            }

            reader.close();
            
            // Display final metrics
            System.out.println("\n=== Final Test Results ===");
            displayFinalMetrics();
            
            // Save test results to file
            saveTestResults(packetCount);

        } catch (Exception e) {
            e.printStackTrace();
        }
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

        System.out.printf("\nCurrent Metrics:\n" +
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
    }

    private static void displayFinalMetrics() {
        double avgAccuracy = accuracyHistory.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        double avgPrecision = precisionHistory.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        double avgRecall = recallHistory.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        double avgF1Score = f1ScoreHistory.stream().mapToDouble(Double::doubleValue).average().orElse(0);

        System.out.printf("\nFinal Performance Metrics:\n" +
            "Average Accuracy: %.2f%%\n" +
            "Average Precision: %.2f%%\n" +
            "Average Recall: %.2f%%\n" +
            "Average F1 Score: %.2f%%\n" +
            "Total True Positives: %d\n" +
            "Total False Positives: %d\n" +
            "Total True Negatives: %d\n" +
            "Total False Negatives: %d\n",
            avgAccuracy, avgPrecision, avgRecall, avgF1Score,
            truePositives, falsePositives, trueNegatives, falseNegatives);
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

    private static void saveTestResults(int totalPackets) {
        try (java.io.FileWriter fw = new java.io.FileWriter("test_results.txt")) {
            fw.write("=== Test Results ===\n");
            fw.write(String.format("Total Packets Tested: %d\n", totalPackets));
            fw.write(String.format("True Positives: %d\n", truePositives));
            fw.write(String.format("False Positives: %d\n", falsePositives));
            fw.write(String.format("True Negatives: %d\n", trueNegatives));
            fw.write(String.format("False Negatives: %d\n", falseNegatives));
            
            double accuracy = calculateAccuracy();
            double precision = calculatePrecision();
            double recall = calculateRecall();
            double f1Score = calculateF1Score(precision, recall);
            
            fw.write("\nPerformance Metrics:\n");
            fw.write(String.format("Accuracy: %.2f%%\n", accuracy));
            fw.write(String.format("Precision: %.2f%%\n", precision));
            fw.write(String.format("Recall: %.2f%%\n", recall));
            fw.write(String.format("F1 Score: %.2f%%\n", f1Score));
            
            System.out.println("\nTest results saved to test_results.txt");
        } catch (Exception e) {
            System.out.println("Error saving test results: " + e.getMessage());
        }
    }
}













































//package com.example.rl;
//
//import com.example.util.PacketReader;
//import com.example.util.PacketReaderFactory;
//import org.pcap4j.packet.Packet;
//
//public class Tester {
//    public static double runTest(String pcapFile, String modelFile) {
//        int total = 0;
//        int correct = 0;
//
//        try {
//            PacketReader reader = PacketReaderFactory.createPacketReader("offline", pcapFile);
//            Environment env = new Environment();
//            RLAgent agent = new RLAgent();
//
//            // Load trained model
//            agent.loadModel(modelFile);
//
//            Packet packet;
//            while ((packet = reader.getNextPacket()) != null) {
//                State state = env.extractState(packet);
//                Action action = agent.chooseAction(state); // Use learned Q-values
//                boolean isMalicious = env.isMalicious(packet);
//
//                // Check correctness
//                if ((action == Action.BLOCK && isMalicious) || (action == Action.ALLOW && !isMalicious)) {
//                    correct++;
//                }
//
//                total++;
//            }
//
//            reader.close();
//        } catch (Exception e) {
//            e.printStackTrace();
//            return -1; // Return -1 if there's an error
//        }
//
//        if (total == 0) {
//            return 0; // Avoid division by zero
//        }
//
//        return (double) correct / total * 100; // Correctly calculate accuracy as a percentage
//
//    }
//}
