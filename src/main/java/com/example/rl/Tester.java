package com.example.rl;

import com.example.util.PacketReader;
import com.example.util.PacketReaderFactory;
import org.pcap4j.packet.Packet;

public class Tester {
    public static void main(String[] args) {
        try {
            PacketReader reader = PacketReaderFactory.createPacketReader("offline", "test.pcapng");
            Environment env = new Environment();
            RLAgent agent = new RLAgent();

            // Load training data
            agent.train("test_csv.csv");

            Packet packet;
            int total = 0, correct = 0;

            while ((packet = reader.getNextPacket()) != null) {
                State state = env.extractState(packet);
                Action action = agent.getAction(state);
                boolean isMalicious = env.isMalicious(packet);

                System.out.printf("Packet: %s | Predicted: %s | Ground Truth: %s\n",
                        state, action, isMalicious ? "BLOCK" : "ALLOW");

                // Check correctness
                if ((!action.isAllowed() && isMalicious) || (action.isAllowed() && !isMalicious)) {
                    correct++;
                }

                total++;
            }

            reader.close();

            System.out.printf("Accuracy: %.2f%% (%d/%d)\n", 100.0 * correct / total, correct, total);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}













































//package com.example.rl;
//
//import com.example.util.PacketReader;
//import com.example.util.PacketReaderFactory;
//import org.pcap4j.packet.Packet;
//
//public class Tester {
//    public static double runTest(String pcapFile, String modelFile) {
//        int total = 0;
//        int correct = 0;
//
//        try {
//            PacketReader reader = PacketReaderFactory.createPacketReader("offline", pcapFile);
//            Environment env = new Environment();
//            RLAgent agent = new RLAgent();
//
//            // Load trained model
//            agent.loadModel(modelFile);
//
//            Packet packet;
//            while ((packet = reader.getNextPacket()) != null) {
//                State state = env.extractState(packet);
//                Action action = agent.chooseAction(state); // Use learned Q-values
//                boolean isMalicious = env.isMalicious(packet);
//
//                // Check correctness
//                if ((action == Action.BLOCK && isMalicious) || (action == Action.ALLOW && !isMalicious)) {
//                    correct++;
//                }
//
//                total++;
//            }
//
//            reader.close();
//        } catch (Exception e) {
//            e.printStackTrace();
//            return -1; // Return -1 if there's an error
//        }
//
//        if (total == 0) {
//            return 0; // Avoid division by zero
//        }
//
//        return (double) correct / total * 100; // Correctly calculate accuracy as a percentage
//
//    }
//}
