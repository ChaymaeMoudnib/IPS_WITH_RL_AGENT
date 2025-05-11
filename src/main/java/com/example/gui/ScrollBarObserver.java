package com.example.gui;

import javax.swing.*;
import com.example.designpatterns.ObserverPattern.Observer;
// import com.example.concurrent.*;

public class ScrollBarObserver implements Observer {
    private JTextArea textArea;
    private int counter = 0;

    public ScrollBarObserver(JTextArea textArea) {
        this.textArea = textArea;
    }

    @Override
    public synchronized void update(String message) {
        // Update UI on the Event Dispatch Thread
        SwingUtilities.invokeLater(() -> {
            try {
                // Format the packet information
                String formattedMessage = String.format("[Packet #%d]\n%s\n", counter++, message);
                textArea.append(formattedMessage);
                
                // Auto-scroll to the bottom
                textArea.setCaretPosition(textArea.getDocument().getLength());
                
                // Limit the number of displayed packets to prevent memory issues
                if (counter > 1000) {
                    textArea.setText(textArea.getText().substring(textArea.getText().indexOf("\n") + 1));
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }
}
