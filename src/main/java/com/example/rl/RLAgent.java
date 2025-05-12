package com.example.rl;

import java.io.*;
import java.util.*;

public class RLAgent {
    private Map<State, Map<Boolean, Double>> qTable;
    private Map<State, Integer> stateVisits;
    private int allowedCount;
    private int blockedCount;
    private double currentConfidence;
    
    // Hyperparameters
    private static final double INITIAL_EPSILON = 0.3;
    private static final double MIN_EPSILON = 0.01;
    private static final double EPSILON_DECAY = 0.995;
    private static final double LEARNING_RATE = 0.1;
    private static final double DISCOUNT_FACTOR = 0.9;
    private static final double MIN_CONFIDENCE = 0.5;
    private static final int CONFIDENCE_VISITS_THRESHOLD = 5;
    
    private double epsilon;
    private Action lastAction;
    
    public RLAgent() {
        this.qTable = new HashMap<>();
        this.stateVisits = new HashMap<>();
        this.allowedCount = 0;
        this.blockedCount = 0;
        this.epsilon = INITIAL_EPSILON;
        this.currentConfidence = MIN_CONFIDENCE;
    }
    
    public void train(String csvFile) {
        int totalLines = 0;
        int processedLines = 0;
        
        // First pass: count total lines
        try (BufferedReader br = new BufferedReader(new FileReader(csvFile))) {
            br.readLine(); // Skip header
            while (br.readLine() != null) totalLines++;
        } catch (IOException e) {
            throw new RuntimeException("Failed to count lines in CSV: " + e.getMessage());
        }
        
        // Second pass: actual training
        try (BufferedReader br = new BufferedReader(new FileReader(csvFile))) {
            br.readLine(); // Skip header
            String line;
            
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length < 6) continue;
                
                State state = new State(
                    parts[0], // protocol
                    parts[1], // srcPort
                    parts[2], // srcIP
                    parts[3], // destPort
                    parts[4]  // destIP
                );
                
                boolean isAllowed = Boolean.parseBoolean(parts[5]);
                double reward = calculateReward(isAllowed, parts);
                
                // Enhanced training with multiple updates for important states
                updateQValue(state, isAllowed, reward);
                
                // Additional training for critical states
                if (isCriticalState(state)) {
                    // Extra training iterations for critical states
                    for (int i = 0; i < 3; i++) {
                        updateQValue(state, isAllowed, reward * 1.5);
                    }
                }
                
                // Update state visits
                stateVisits.merge(state, 1, Integer::sum);
                
                // Adaptive epsilon decay
                processedLines++;
                double progress = (double) processedLines / totalLines;
                epsilon = Math.max(MIN_EPSILON, INITIAL_EPSILON * Math.pow(EPSILON_DECAY, progress * 100));
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to train from CSV: " + e.getMessage());
        }
    }
    
    private boolean isCriticalState(State state) {
        // Define critical states that need more training
        String protocol = state.getProtocol();
        String destPort = state.getDestPort();
        
        // Critical ports and protocols
        return protocol.equals("TCP") && (
            destPort.equals("80") ||    // HTTP
            destPort.equals("443") ||   // HTTPS
            destPort.equals("22") ||    // SSH
            destPort.equals("3389")     // RDP
        );
    }
    
    private double calculateReward(boolean isAllowed, String[] parts) {
        double baseReward = isAllowed ? 1.0 : -1.0;
        
        // Enhanced reward calculation
        if (parts.length > 6) {
            String severity = parts[6];
            if (severity != null) {
                switch (severity.toLowerCase()) {
                    case "high":
                        baseReward *= 2.5;  // Increased from 2.0
                        break;
                    case "medium":
                        baseReward *= 2.0;  // Increased from 1.5
                        break;
                    case "low":
                        baseReward *= 1.5;  // Increased from 1.0
                        break;
                }
            }
        }
        
        // Additional reward for consistent decisions
        State state = new State(parts[0], parts[1], parts[2], parts[3], parts[4]);
        int visits = stateVisits.getOrDefault(state, 0);
        if (visits > CONFIDENCE_VISITS_THRESHOLD) {
            baseReward *= 1.2;  // 20% bonus for well-known states
        }
        
        return baseReward;
    }
    
    public void updateQValue(State state, boolean action, double reward) {
        Map<Boolean, Double> stateValues = qTable.computeIfAbsent(state, k -> new HashMap<>());
        double oldValue = stateValues.getOrDefault(action, 0.0);
        
        // Dynamic learning rate based on visits
        int visits = stateVisits.getOrDefault(state, 0);
        double dynamicLR = LEARNING_RATE / (1 + 0.1 * visits);
        
        double newValue = oldValue + dynamicLR * (reward + DISCOUNT_FACTOR * getMaxQValue(state) - oldValue);
        stateValues.put(action, newValue);
    }
    
    private double getMaxQValue(State state) {
        Map<Boolean, Double> stateValues = qTable.get(state);
        if (stateValues == null || stateValues.isEmpty()) return 0.0;
        return Collections.max(stateValues.values());
    }
    
    public Action getAction(State state) {
        Map<Boolean, Double> stateValues = qTable.computeIfAbsent(state, k -> new HashMap<>());
        int stateVisitCount = stateVisits.getOrDefault(state, 0);
        
        // Exploration vs exploitation
        if (Math.random() < epsilon) {
            boolean randomAction = Math.random() < 0.5;
            double confidence = calculateConfidence(state, randomAction);
            updateCounter(randomAction);
            lastAction = new Action(randomAction, confidence);
            return lastAction;
        }
        
        // Get the action with highest Q-value
        boolean bestAction = false;
        double maxValue = Double.NEGATIVE_INFINITY;
        
        for (Map.Entry<Boolean, Double> entry : stateValues.entrySet()) {
            if (entry.getValue() > maxValue) {
                maxValue = entry.getValue();
                bestAction = entry.getKey();
            }
        }
        
        // If no values exist, use default policy
        if (maxValue == Double.NEGATIVE_INFINITY) {
            updateCounter(true);
            lastAction = new Action(true, MIN_CONFIDENCE);
            return lastAction;
        }
        
        double confidence = calculateConfidence(state, bestAction);
        lastAction = new Action(bestAction, confidence);
        updateCounter(bestAction);
        return lastAction;
    }
    
    private double calculateConfidence(State state, boolean action) {
        int visits = stateVisits.getOrDefault(state, 0);
        Map<Boolean, Double> stateValues = qTable.get(state);
        
        if (stateValues == null || !stateValues.containsKey(action)) {
            return MIN_CONFIDENCE;
        }
        
        double qValue = stateValues.get(action);
        // Faster confidence building with visits
        double visitFactor = Math.min(1.0, visits / (double)CONFIDENCE_VISITS_THRESHOLD);
        
        // Improved confidence calculation
        double baseConfidence = Math.abs(qValue) / (1.0 + Math.abs(qValue));
        double confidence = MIN_CONFIDENCE + (1.0 - MIN_CONFIDENCE) * baseConfidence * visitFactor;
        
        // Add bonus for consistent decisions
        if (visits > CONFIDENCE_VISITS_THRESHOLD) {
            confidence += 0.1;  // Small bonus for well-known states
        }
        
        return Math.min(1.0, confidence);  // Ensure confidence doesn't exceed 1.0
    }
    
    private void updateCounter(boolean allowed) {
        if (allowed) allowedCount++;
        else blockedCount++;
    }
    
    public int getAllowedCount() {
        return allowedCount;
    }
    
    public int getBlockedCount() {
        return blockedCount;
    }
    
    public Action getLastAction() {
        return lastAction;
    }
    
    public double getCurrentConfidence() {
        return currentConfidence;
    }
    
    public void resetCounters() {
        allowedCount = 0;
        blockedCount = 0;
    }

    public void saveModel(String filePath) {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath))) {
            // Save all model state
            oos.writeObject(qTable);
            oos.writeObject(stateVisits);
            oos.writeDouble(epsilon);
            oos.writeDouble(currentConfidence);
            oos.writeInt(allowedCount);
            oos.writeInt(blockedCount);
        } catch (IOException e) {
            throw new RuntimeException("Failed to save model: " + e.getMessage());
        }
    }

    public void loadModel(String filePath) {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            // Load all model state
            qTable = (Map<State, Map<Boolean, Double>>) ois.readObject();
            stateVisits = (Map<State, Integer>) ois.readObject();
            epsilon = ois.readDouble();
            currentConfidence = ois.readDouble();
            allowedCount = ois.readInt();
            blockedCount = ois.readInt();
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException("Failed to load model: " + e.getMessage());
        }
    }
}
