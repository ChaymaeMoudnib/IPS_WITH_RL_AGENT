package com.example.gui.components;

import javax.swing.*;
import java.awt.*;

public class RLDecisionsPanel extends JPanel {
    private JTextPane rlDecisionsArea;

    public RLDecisionsPanel() {
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createTitledBorder("RL Prevention Decisions"));
        initializeComponents();
        setupLayout();
    }

    private void initializeComponents() {
        rlDecisionsArea = new JTextPane();
        rlDecisionsArea.setEditable(false);
        rlDecisionsArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        rlDecisionsArea.setBackground(new Color(250, 250, 250));
    }

    private void setupLayout() {
        JScrollPane rlScroll = new JScrollPane(rlDecisionsArea);
        add(rlScroll, BorderLayout.CENTER);
    }

    public void appendDecision(String decision) {
        javax.swing.text.Style style = rlDecisionsArea.addStyle("Color Style", null);

        try {
            if (decision.contains("ALLOWED")) {
                javax.swing.text.StyleConstants.setForeground(style, new Color(0, 150, 0));
            } else if (decision.contains("BLOCKED")) {
                javax.swing.text.StyleConstants.setForeground(style, new Color(200, 0, 0));
            }

            ((javax.swing.text.StyledDocument) rlDecisionsArea.getDocument()).insertString(
                    rlDecisionsArea.getDocument().getLength(), decision + "\n", style);
            rlDecisionsArea.setCaretPosition(rlDecisionsArea.getDocument().getLength());
        } catch (javax.swing.text.BadLocationException e) {
            e.printStackTrace();
        }
    }

    public void clear() {
        rlDecisionsArea.setText("");
    }

    public JTextPane getRLDecisionsArea() {
        return rlDecisionsArea;
    }
} 