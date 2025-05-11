package com.example.util;

import javax.mail.*;
import javax.mail.internet.*;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.IOException;
import com.example.detection.Alert;
import com.example.detection.Severity;
import java.util.Map;

public class EmailService {
    private static EmailService instance;
    private Properties emailProperties;
    private String username;
    private String password;
    private String adminEmail;
    private boolean isConfigured = false;

    private EmailService() {
        loadEmailConfig();
    }

    public static EmailService getInstance() {
        if (instance == null) {
            instance = new EmailService();
        }
        return instance;
    }

    private void loadEmailConfig() {
        try {
            emailProperties = new Properties();
            FileInputStream configFile = new FileInputStream("config/email.properties");
            emailProperties.load(configFile);
            
            username = emailProperties.getProperty("mail.username");
            password = emailProperties.getProperty("mail.password");
            adminEmail = emailProperties.getProperty("mail.admin");
            
            isConfigured = (username != null && password != null && adminEmail != null);
            
            if (!isConfigured) {
                System.err.println("Email configuration is incomplete. Please check email.properties file.");
            }
        } catch (IOException e) {
            System.err.println("Error loading email configuration: " + e.getMessage());
        }
    }

    public void sendAlertEmail(Alert alert) {
        if (!isConfigured) {
            System.err.println("Cannot send email: Email service is not properly configured.");
            return;
        }

        // Only send emails for CRITICAL and HIGH severity alerts
        if (alert.getSeverity() != Severity.CRITICAL && alert.getSeverity() != Severity.HIGH) {
            return;
        }

        // Set up mail server properties
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", emailProperties.getProperty("mail.smtp.host"));
        props.put("mail.smtp.port", emailProperties.getProperty("mail.smtp.port"));

        // Create session
        Session session = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(username, password);
            }
        });

        try {
            // Create message
            Message emailMessage = new MimeMessage(session);
            emailMessage.setFrom(new InternetAddress(username));
            emailMessage.setRecipients(Message.RecipientType.TO, InternetAddress.parse(adminEmail));
            emailMessage.setSubject("[IDPS Alert] " + alert.getType().getDescription());

            // Create message body with HTML formatting
            String htmlBody = String.format(
                "<html><body>" +
                "<h2 style='color: %s;'>IDPS Alert</h2>" +
                "<p><strong>Severity:</strong> %s</p>" +
                "<p><strong>Time:</strong> %s</p>" +
                "<p><strong>Type:</strong> %s</p>" +
                "<p><strong>Message:</strong> %s</p>" +
                "<p><strong>Packet Details:</strong></p>" +
                "<pre>%s</pre>" +
                "</body></html>",
                getSeverityColor(alert.getSeverity()),
                alert.getSeverity(),
                alert.getTimestamp(),
                alert.getType().getDescription(),
                alert.getMessage(),
                formatPacketData(alert.getPacketData())
            );

            emailMessage.setContent(htmlBody, "text/html");

            // Send message
            Transport.send(emailMessage);
            System.out.println("Alert email sent successfully to " + adminEmail);

        } catch (MessagingException e) {
            System.err.println("Error sending alert email: " + e.getMessage());
        }
    }

    private String getSeverityColor(Severity severity) {
        switch (severity) {
            case CRITICAL:
                return "#FF0000"; // Red
            case HIGH:
                return "#FF4500"; // Orange Red
            case MEDIUM:
                return "#FFA500"; // Orange
            case LOW:
                return "#FFD700"; // Gold
            default:
                return "#000000"; // Black
        }
    }

    private String formatPacketData(Map<String, String> packetData) {
        if (packetData == null) return "No packet data available";
        
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : packetData.entrySet()) {
            sb.append(entry.getKey())
              .append(": ")
              .append(entry.getValue())
              .append("\n");
        }
        return sb.toString();
    }
} 