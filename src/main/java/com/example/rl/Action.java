package com.example.rl;

public class Action {
    private final boolean allowed;
    private final double confidence;
    
    public Action(boolean allowed, double confidence) {
        this.allowed = allowed;
        this.confidence = confidence;
    }
    
    public boolean isAllowed() {
        return allowed;
    }
    
    public double getConfidence() {
        return confidence;
    }
    
    @Override
    public String toString() {
        return String.format("%s (conf: %.2f)", 
            allowed ? "ALLOW" : "BLOCK", 
            confidence);
    }
}
