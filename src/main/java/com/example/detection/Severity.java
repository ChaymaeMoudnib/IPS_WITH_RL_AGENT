package com.example.detection;

public enum Severity {
    LOW("Low"),
    MEDIUM("Medium"),
    HIGH("High"),
    CRITICAL("Critical");

    private final String description;

    Severity(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
} 