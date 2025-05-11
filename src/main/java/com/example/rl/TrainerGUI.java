package com.example.rl;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;

public class TrainerGUI {

    private JTextPane textPane;
    private JButton stopButton;
    private JButton continueButton;

    public TrainerGUI() {
        // Create the frame
        JFrame frame = new JFrame("RL Training");
        frame.setSize(600, 400);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        // Create the text pane for output with a styled document
        textPane = new JTextPane();
        textPane.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(textPane);

        // Create Stop button
        stopButton = new JButton("Stop Training");
        stopButton.addActionListener(e -> {
            Trainer.stopTraining();
            stopButton.setEnabled(false); // Disable stop button after stopping training
            continueButton.setEnabled(true); // Enable continue button after stopping training
        });

        // Create Continue button
        continueButton = new JButton("Continue Training");
        continueButton.addActionListener(e -> {
            Trainer.continueTraining();
            stopButton.setEnabled(true); // Enable stop button again after continuing training
            continueButton.setEnabled(false); // Disable continue button when training is ongoing
        });

        // Initially disable Continue button
        continueButton.setEnabled(false);

        // Set up layout
        JPanel panel = new JPanel();
        panel.add(stopButton);
        panel.add(continueButton);

        frame.getContentPane().add(scrollPane, "Center");
        frame.getContentPane().add(panel, "South");
        frame.setVisible(true);
    }

    public void updateTextPane(String message, boolean isMalicious) {
        // Create a styled document and a style for red color
        StyledDocument doc = textPane.getStyledDocument();
        SimpleAttributeSet redText = new SimpleAttributeSet();
        SimpleAttributeSet greenText = new SimpleAttributeSet();

        // Set text color
        if (isMalicious) {
            StyleConstants.setForeground(redText, Color.RED);
        } else {
            StyleConstants.setForeground(greenText, Color.GREEN);
        }

        try {
            doc.insertString(doc.getLength(), message, isMalicious ? redText : greenText);
        } catch (BadLocationException e) {
            e.printStackTrace();
        }

        // Auto-scroll to the bottom
        textPane.setCaretPosition(textPane.getDocument().getLength());
    }
}

