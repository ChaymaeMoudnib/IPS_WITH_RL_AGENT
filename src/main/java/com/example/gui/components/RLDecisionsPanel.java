package com.example.gui.components;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;

public class RLDecisionsPanel extends JPanel {
    private JTextPane rlDecisionsArea;
    private JLabel decisionCountLabel;
    private int decisionCount = 0;

    public RLDecisionsPanel() {
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("RL Prevention Decisions"),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));
        setBackground(new Color(245, 245, 245));
        initializeComponents();
        setupLayout();
    }

    private void initializeComponents() {
        rlDecisionsArea = new JTextPane();
        rlDecisionsArea.setEditable(false);
        rlDecisionsArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        rlDecisionsArea.setBackground(new Color(250, 250, 250));
        rlDecisionsArea.setMargin(new Insets(5, 5, 5, 5));

        decisionCountLabel = new JLabel("Decisions: 0");
        decisionCountLabel.setFont(new Font("Arial", Font.BOLD, 12));
        decisionCountLabel.setForeground(new Color(0, 100, 0));
    }

    private void setupLayout() {
        JScrollPane rlScroll = new JScrollPane(rlDecisionsArea);
        rlScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        rlScroll.setBorder(BorderFactory.createLineBorder(new Color(200, 200, 200)));

        JPanel headerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        headerPanel.setBackground(new Color(245, 245, 245));
        headerPanel.add(decisionCountLabel);

        add(headerPanel, BorderLayout.NORTH);
        add(rlScroll, BorderLayout.CENTER);
    }

    public void appendDecision(String decision) {
        javax.swing.text.Style style = rlDecisionsArea.addStyle("Color Style", null);

        try {
            if (decision.contains("ALLOWED")) {
                javax.swing.text.StyleConstants.setForeground(style, new Color(0, 150, 0));
                javax.swing.text.StyleConstants.setBold(style, true);
            } else if (decision.contains("BLOCKED")) {
                javax.swing.text.StyleConstants.setForeground(style, new Color(200, 0, 0));
                javax.swing.text.StyleConstants.setBold(style, true);
            }

            ((javax.swing.text.StyledDocument) rlDecisionsArea.getDocument()).insertString(
                    rlDecisionsArea.getDocument().getLength(), 
                    String.format("Decision #%d: %s\n", ++decisionCount, decision), 
                    style);
            rlDecisionsArea.setCaretPosition(rlDecisionsArea.getDocument().getLength());
            decisionCountLabel.setText("Decisions: " + decisionCount);
        } catch (javax.swing.text.BadLocationException e) {
            e.printStackTrace();
        }
    }

    public void clear() {
        rlDecisionsArea.setText("");
        decisionCount = 0;
        decisionCountLabel.setText("Decisions: 0");
    }

    public JTextPane getRLDecisionsArea() {
        return rlDecisionsArea;
    }
} 