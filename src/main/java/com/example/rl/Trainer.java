package com.example.rl;

import com.example.util.PacketReader;
import com.example.util.PacketReaderFactory;
import org.pcap4j.packet.Packet;

import javax.swing.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class Trainer {

    private static int totalReward = 0;
    private static volatile boolean stopTraining = false; // Flag to stop the training loop
    private static TrainerGUI gui;

    public static void main(String[] args) {
        // Set up the GUI
        gui = new TrainerGUI();

        // Create and start the training process
        startTraining();
    }

    public static void startTraining() {
        // Run the training loop
        FileWriter fw = null;

        try {
            PacketReader reader = PacketReaderFactory.createPacketReader("offline", "start.pcapng");
            Environment env = new Environment(); // Simulated environment
            RLAgent agent = new RLAgent();       // Your RL model

            // Write CSV header if file doesn't exist
            File csvFile = new File("features.csv");
            boolean headerExists = csvFile.exists();
            fw = new FileWriter(csvFile, true);

            if (!headerExists) {
                fw.write("protocol,srcPort,srcIP,destPort,destIP,isMalicious,action\n");
            }

            Packet packet;
            while ((packet = reader.getNextPacket()) != null && !stopTraining) {
                // Extract features
                State state = env.extractState(packet);

                // RL decision logic
                Action action = agent.getAction(state);
                boolean isMalicious = env.isMalicious(packet);

                String output = String.format("Packet: %s, malicious=%b, action=%s%n", state, isMalicious, action);
                gui.updateTextPane(output, isMalicious);

                int reward = env.evaluate(action, isMalicious);
                totalReward += reward;

                // Write all data to CSV
                fw.write(state.getProtocol() + "," +
                        state.getSrcPort() + "," +
                        state.getSrcIP() + "," +
                        state.getDestPort() + "," +
                        state.getDestIP() + "," +
                        isMalicious + "," +
                        action.isAllowed() + "\n");

                // Also output state to GUI
                gui.updateTextPane("Extracted state: " + state + "\n", isMalicious);

                // Simulate a short delay to make training less intense (for testing)
                Thread.sleep(100);
            }

            reader.close();
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

    public static void stopTraining() {
        stopTraining = true;
    }

    public static void continueTraining() {
        stopTraining = false;
        totalReward = 0; // Optionally reset reward when continuing training
        gui.updateTextPane("Continuing training...\n", false);
        startTraining(); // Restart the training process without calling main()
    }
}
