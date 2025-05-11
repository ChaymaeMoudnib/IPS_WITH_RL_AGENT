package com.example.rl;

import javafx.application.Application;
import javafx.beans.binding.Bindings;
import javafx.beans.property.DoubleProperty;
import javafx.beans.property.SimpleDoubleProperty;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.VBox;
//import javafx.stage.Stage;
//
//public class TesterGUI extends Application {
//
//    private DoubleProperty accuracy = new SimpleDoubleProperty(-1);
//
//    @Override
//    public void start(Stage primaryStage) {
//        // UI elements
//        Label statusLabel = new Label("Test not started");
//        Button startButton = new Button("Start Test");
//
//        // Bind the status label to the accuracy
//        statusLabel.textProperty().bind(Bindings.format("Accuracy: %.2f%%", accuracy));
//
//        startButton.setOnAction(event -> {
//            startTest(statusLabel);
//        });
//
//        VBox vbox = new VBox(10, startButton, statusLabel);
//        vbox.setMinWidth(300);
//        vbox.setMinHeight(200);
//
//        Scene scene = new Scene(vbox);
//        primaryStage.setTitle("RL Packet Tester");
//        primaryStage.setScene(scene);
//        primaryStage.show();
//    }
//
//    private void startTest(Label statusLabel) {
//        // Simulate running the test
//        new Thread(() -> {
//            double result = Tester.runTest("test.pcapng", "RL_IPS.zip");
//            accuracy.set(result);
//
//            if (result == -1) {
//                statusLabel.setText("Error occurred during testing.");
//            } else {
//                statusLabel.setText(String.format("Accuracy: %.2f%%", result));
//            }
//        }).start();
//    }
//
//
//    public static void main(String[] args) {
//        launch(args);
//    }
//}
