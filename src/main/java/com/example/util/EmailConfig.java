package com.example.util;

import java.io.*;
import java.util.Properties;
import java.util.logging.Logger;
import java.util.logging.Level;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class EmailConfig {
    private static final Logger LOGGER = Logger.getLogger(EmailConfig.class.getName());
    private static final String CONFIG_FILE = "email_config.properties";
    private static final String ENCRYPTION_KEY = "IDS_SEC_KEY_2024"; // Simple encryption key

    private String username;
    private String password;
    private String adminEmail;
    private boolean enabled;

    public EmailConfig() {
        loadConfig();
    }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    
    public String getAdminEmail() { return adminEmail; }
    public void setAdminEmail(String adminEmail) { this.adminEmail = adminEmail; }
    
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public void saveConfig() {
        Properties props = new Properties();
        try {
            // Encrypt sensitive data
            props.setProperty("username", encrypt(username));
            props.setProperty("password", encrypt(password));
            props.setProperty("adminEmail", encrypt(adminEmail));
            props.setProperty("enabled", String.valueOf(enabled));

            File configDir = new File("config");
            if (!configDir.exists()) {
                configDir.mkdir();
            }

            try (FileOutputStream out = new FileOutputStream("config/" + CONFIG_FILE)) {
                props.store(out, "Email Configuration");
                LOGGER.info("Email configuration saved successfully");
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to save email configuration", e);
        }
    }

    public void loadConfig() {
        Properties props = new Properties();
        File configFile = new File("config/" + CONFIG_FILE);
        
        if (!configFile.exists()) {
            LOGGER.info("No existing email configuration found");
            return;
        }

        try (FileInputStream in = new FileInputStream(configFile)) {
            props.load(in);

            // Decrypt sensitive data
            username = decrypt(props.getProperty("username", ""));
            password = decrypt(props.getProperty("password", ""));
            adminEmail = decrypt(props.getProperty("adminEmail", ""));
            enabled = Boolean.parseBoolean(props.getProperty("enabled", "false"));

            LOGGER.info("Email configuration loaded successfully");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to load email configuration", e);
        }
    }

    private String encrypt(String value) throws Exception {
        if (value == null) return "";
        
        SecretKey key = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(value.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private String decrypt(String encrypted) throws Exception {
        if (encrypted == null || encrypted.isEmpty()) return "";
        
        SecretKey key = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encrypted));
        return new String(decrypted);
    }

    public boolean hasValidConfig() {
        return username != null && !username.trim().isEmpty() &&
               password != null && !password.trim().isEmpty() &&
               adminEmail != null && !adminEmail.trim().isEmpty();
    }

    public void clearConfig() {
        // Clear memory
        username = null;
        password = null;
        adminEmail = null;
        enabled = false;

        // Delete config file
        File configFile = new File("config/" + CONFIG_FILE);
        if (configFile.exists()) {
            if (configFile.delete()) {
                LOGGER.info("Email configuration file deleted successfully");
            } else {
                LOGGER.warning("Failed to delete email configuration file");
            }
        }
    }
} 