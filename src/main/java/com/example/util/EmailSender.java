package com.example.util;

import javax.mail.*;
import javax.mail.internet.*;
import java.util.Properties;
import java.util.logging.Logger;
import java.util.logging.Level;

public class EmailSender {
    private static final Logger LOGGER = Logger.getLogger(EmailSender.class.getName());
    
    private final String username;
    private final String password;
    private final String smtpHost;
    private final int smtpPort;
    private final String adminEmail;
    
    public EmailSender(String username, String password, String smtpHost, int smtpPort, String adminEmail) {
        // Validate input parameters
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be empty");
        }
        if (password == null || password.trim().isEmpty()) {
            throw new IllegalArgumentException("Password cannot be empty");
        }
        if (adminEmail == null || adminEmail.trim().isEmpty()) {
            throw new IllegalArgumentException("Admin email cannot be empty");
        }
        if (!isValidEmail(username) || !isValidEmail(adminEmail)) {
            throw new IllegalArgumentException("Invalid email format");
        }

        this.username = username;
        this.password = password;
        this.smtpHost = smtpHost;
        this.smtpPort = smtpPort;
        this.adminEmail = adminEmail;
        
        LOGGER.info("EmailSender initialized with username: " + username + ", SMTP host: " + smtpHost);
    }
    
    public void sendAlertEmail(String subject, String content) throws MessagingException {
        LOGGER.info("Attempting to send email to " + adminEmail);
        LOGGER.info("Subject: " + subject);
        
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", smtpHost);
        props.put("mail.smtp.port", smtpPort);
        props.put("mail.smtp.ssl.trust", smtpHost);
        props.put("mail.smtp.ssl.protocols", "TLSv1.2");
        props.put("mail.debug", "true");  // Enable debug mode
        
        LOGGER.info("Mail properties configured: " + props);
        
        try {
            Session session = Session.getInstance(props, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(username, password);
                }
            });
            
            // Enable session debugging
            session.setDebug(true);
            
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(username));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(adminEmail));
            message.setSubject(subject);
            
            // Create multipart message
            Multipart multipart = new MimeMultipart();
            
            // Create text part
            MimeBodyPart textPart = new MimeBodyPart();
            textPart.setText(content, "UTF-8", "plain");
            multipart.addBodyPart(textPart);
            
            // Set message content
            message.setContent(multipart);
            
            LOGGER.info("Sending email...");
            Transport.send(message);
            LOGGER.info("Alert email sent successfully to " + adminEmail);
            
        } catch (MessagingException e) {
            LOGGER.log(Level.SEVERE, "Failed to send alert email", e);
            LOGGER.severe("Error details: " + e.getMessage());
            if (e.getNextException() != null) {
                LOGGER.severe("Nested exception: " + e.getNextException().getMessage());
            }
            throw e; // Rethrow to handle in GUI
        }
    }
    
    private boolean isValidEmail(String email) {
        try {
            InternetAddress emailAddr = new InternetAddress(email);
            emailAddr.validate();
            return true;
        } catch (AddressException e) {
            return false;
        }
    }
    
    public static EmailSender createDefaultSender(String username, String password, String adminEmail) {
        LOGGER.info("Creating default email sender for: " + username);
        try {
            return new EmailSender(
                username,
                password,
                "smtp.gmail.com",  // Default SMTP host for Gmail
                587,               // Default SMTP port for Gmail
                adminEmail
            );
        } catch (Exception e) {
            LOGGER.severe("Failed to create EmailSender: " + e.getMessage());
            throw e;
        }
    }
    
    // Test connection without sending email
    public boolean testConnection() {
        LOGGER.info("Testing email connection...");
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", smtpHost);
        props.put("mail.smtp.port", smtpPort);
        props.put("mail.smtp.ssl.trust", smtpHost);
        props.put("mail.smtp.ssl.protocols", "TLSv1.2");
        
        try {
            Session session = Session.getInstance(props, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(username, password);
                }
            });
            
            Transport transport = session.getTransport("smtp");
            transport.connect(smtpHost, smtpPort, username, password);
            transport.close();
            
            LOGGER.info("Email connection test successful");
            return true;
        } catch (Exception e) {
            LOGGER.severe("Email connection test failed: " + e.getMessage());
            return false;
        }
    }
} 