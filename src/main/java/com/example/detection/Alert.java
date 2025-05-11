package com.example.detection;

import java.util.Map;
import java.util.Date;

public class Alert {
    private final AlertType type;
    private final Severity severity;
    private final String message;
    private final Date timestamp;
    private Map<String, String> packetData;

    public Alert(AlertType type, Severity severity, String message) {
        this.type = type;
        this.severity = severity;
        this.message = message;
        this.timestamp = new Date();
    }

    public Alert(AlertType type, Severity severity, String message, Map<String, String> packetData) {
        this(type, severity, message);
        this.packetData = packetData;
    }

    public AlertType getType() {
        return type;
    }

    public Severity getSeverity() {
        return severity;
    }

    public String getMessage() {
        return message;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public Map<String, String> getPacketData() {
        return packetData;
    }

    public void setPacketData(Map<String, String> packetData) {
        this.packetData = packetData;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("[")
          .append(timestamp)
          .append("] [")
          .append(severity)
          .append("] ")
          .append(type)
          .append(": ")
          .append(message);

        if (packetData != null) {
            sb.append("\nPacket Details:\n");
            for (Map.Entry<String, String> entry : packetData.entrySet()) {
                sb.append("  ")
                  .append(entry.getKey())
                  .append(": ")
                  .append(entry.getValue())
                  .append("\n");
            }
        }

        return sb.toString();
    }
} 