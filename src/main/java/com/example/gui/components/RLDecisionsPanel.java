package com.example.gui.components;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;

public class RLDecisionsPanel extends JPanel {
    private JTextPane rlDecisionsArea;
    private JLabel decisionCountLabel;
    private JLabel headerLabel;
    private int decisionCount = 0;

    public RLDecisionsPanel() {
        setLayout(new BorderLayout(0, 12));
        setBackground(Color.WHITE);
        setBorder(new CompoundBorder(
            new LineBorder(new Color(230, 230, 230), 1, true),
            new EmptyBorder(18, 18, 18, 18)
        ));
        initializeComponents();
        setupLayout();
    }

    private void initializeComponents() {
        headerLabel = new JLabel("RL Prevention Decisions");
        headerLabel.setFont(new Font("Segoe UI", Font.BOLD, 20));
        headerLabel.setForeground(new Color(33, 97, 140));
        headerLabel.setBorder(new MatteBorder(0, 0, 2, 0, new Color(33, 97, 140)));

        rlDecisionsArea = new JTextPane();
        rlDecisionsArea.setEditable(false);
        rlDecisionsArea.setFont(new Font("Segoe UI", Font.PLAIN, 15));
        rlDecisionsArea.setBackground(new Color(248, 249, 251));
        rlDecisionsArea.setMargin(new Insets(8, 8, 8, 8));
        rlDecisionsArea.setBorder(BorderFactory.createEmptyBorder());

        decisionCountLabel = new JLabel("Decisions: 0");
        decisionCountLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));
        decisionCountLabel.setForeground(new Color(0, 150, 0));
        decisionCountLabel.setBorder(new EmptyBorder(0, 0, 0, 0));
    }

    private void setupLayout() {
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setOpaque(false);
        headerPanel.add(headerLabel, BorderLayout.WEST);
        headerPanel.add(decisionCountLabel, BorderLayout.EAST);

        JScrollPane rlScroll = new JScrollPane(rlDecisionsArea);
        rlScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        rlScroll.setBorder(BorderFactory.createEmptyBorder());
        rlScroll.getViewport().setBackground(new Color(248, 249, 251));

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