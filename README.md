# 🛡️ Network Intrusion Detection System with Reinforcement Learning

A sophisticated Network Intrusion Detection System (NIDS) that combines traditional rule-based detection with Reinforcement Learning (RL) for enhanced security monitoring and threat detection. This system helps you monitor your network traffic, detect potential threats, and learn from patterns to improve security over time.

## ✨ Features

### 🎯 Core Functionality
- Real-time network packet capture and analysis
- Rule-based intrusion detection using Snort rules
- Reinforcement Learning-based decision making
- Multi-threaded packet processing
- Comprehensive traffic statistics and monitoring

### 🖥️ GUI Components
- **Control Panel**: Network interface selection and capture controls
- **Simulation Panel**: Attack simulation tools
- **Packet Display**: Real-time packet information display
- **Statistics Panel**: Traffic and RL performance metrics
- **Log Panel**: Alert and event logging with severity indicators
- **RL Decisions Panel**: Reinforcement Learning decisions display

### 🔒 Security Features
- DDoS attack detection
- SQL injection detection
- Port scanning detection
- Custom rule support
- Real-time threat assessment
- Adaptive learning capabilities

## 📋 Prerequisites

- Java Development Kit (JDK) 11 or higher
- Maven 3.6 or higher
- Network interface with packet capture capabilities
- Administrator/root privileges for packet capture

## 📦 Dependencies

### Core Dependencies
```xml
<dependencies>
    <!-- Packet Capture -->
    <dependency>
        <groupId>org.pcap4j</groupId>
        <artifactId>pcap4j-core</artifactId>
        <version>1.8.2</version>
    </dependency>
    <dependency>
        <groupId>org.pcap4j</groupId>
        <artifactId>pcap4j-packetfactory-static</artifactId>
        <version>1.8.2</version>
    </dependency>

    <!-- GUI -->
    <dependency>
        <groupId>com.formdev</groupId>
        <artifactId>flatlaf</artifactId>
        <version>2.6</version>
    </dependency>

    <!-- Logging -->
    <dependency>
        <groupId>ch.qos.logback</groupId>
        <artifactId>logback-classic</artifactId>
        <version>1.2.11</version>
    </dependency>

    <!-- Testing -->
    <dependency>
        <groupId>junit</groupId>
        <artifactId>junit</artifactId>
        <version>4.13.2</version>
        <scope>test</scope>
    </dependency>
</dependencies>
```

## 🚀 Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/network-ids-rl.git
cd network-ids-rl
```

2. Build the project:
```bash
mvn clean install
```

3. Create required directories:
```bash
mkdir -p logs
mkdir -p rules
```

4. Download Snort rules:
```bash
# Place your snort.rules file in the rules directory
cp path/to/your/snort.rules rules/
```

## ⚙️ Configuration

### Network Interface
The system requires a network interface with packet capture capabilities. Common interfaces include:
- Windows: `\Device\NPF_{GUID}`
- Linux: `eth0`, `wlan0`
- macOS: `en0`, `en1`

### Rule Configuration
1. Place your Snort rules in the `rules/snort.rules` file
2. Custom rules can be added following Snort rule syntax

### RL Model
1. Place your trained RL model in the project root as `trained_model.rl`
2. The model should be compatible with the RLAgent implementation

## 🎮 Usage

### Starting the Application
```bash
java -jar target/network-ids-rl.jar
```

### Basic Operations
1. Select a network interface from the dropdown
2. Click "Start" to begin packet capture
3. Monitor the various panels for:
   - Captured packets
   - Security alerts
   - RL decisions
   - Traffic statistics

### Running a Complete Simulation
1. **Launch the Application**
   ```bash
   java -jar target/network-ids-rl.jar
   ```

2. **Interface Selection**
   - Open the dropdown menu in the Control Panel
   - Select your active network interface
   - Common interfaces:
     - Windows: `\Device\NPF_{GUID}`
     - Linux: `eth0`, `wlan0`
     - macOS: `en0`, `en1`

3. **Start Capture**
   - Click the "Start" button in the Control Panel
   - Wait 2-3 seconds for the capture to initialize
   - The Packet Display panel should start showing incoming packets
   - The Statistics panel will begin updating with traffic data

4. **Enable RL Model**
   - The RL model is automatically loaded at startup
   - Monitor the RL Decisions panel for real-time decisions
   - The model will start learning from the traffic patterns

5. **Customizing Blocking Behavior**
   By default, the system uses passive blocking (monitoring only). To enable active blocking:

   a. **Modify the RLAgent.java file**:
   ```java
   public class RLAgent {
       private boolean activeBlocking = false;  // Set to true for active blocking
       
       public void setActiveBlocking(boolean active) {
           this.activeBlocking = active;
       }
       
       private void handleDecision(Packet packet, Decision decision) {
           if (decision == Decision.BLOCK) {
               if (activeBlocking) {
                   // Implement active blocking logic
                   blockPacket(packet);
               } else {
                   // Log the blocked packet (passive mode)
                   logBlockedPacket(packet);
               }
           }
       }
       
       private void blockPacket(Packet packet) {
           // Add your custom blocking logic here
           // Example: Drop packet, close connection, etc.
       }
   }
   ```

   b. **Add Custom Blocking Rules**:
   ```java
   public class CustomBlockingRules {
       public static void applyBlockingRules(Packet packet) {
           // Add your custom rules
           if (isDDoSAttack(packet)) {
               blockSourceIP(packet.getSourceIP());
           }
           if (isSQLInjection(packet)) {
               blockConnection(packet);
           }
       }
   }
   ```

6. **Monitor the Results**
   - Watch the Log Panel for security alerts
   - Check the Statistics Panel for:
     - Overall accuracy
     - Real-time accuracy
     - Blocked vs. Allowed packets
   - Review the RL Decisions Panel for:
     - Decision confidence levels
     - Learning progress
     - Blocking patterns

7. **Stop and Analyze**
   - Click "Stop" to end the capture
   - Review the collected statistics
   - Export logs if needed
   - Analyze the RL model's performance

### Performance Tips
- Start with passive blocking to understand traffic patterns
- Gradually enable active blocking for specific threats
- Monitor system resources during active blocking
- Adjust blocking rules based on false positive rates
- Regularly update the RL model with new training data

## 🎯 Simulation Scenarios

### 1. DDoS Attack Simulation
```bash
# Using hping3 for SYN flood
hping3 -S -p 80 --flood 192.168.1.100

# Using LOIC (Low Orbit Ion Cannon)
# Download and run LOIC, set target IP and port
```

Expected Behavior:
- High number of SYN packets detected
- RL agent should start blocking suspicious traffic
- Statistics panel shows increased TCP traffic
- Log panel displays DDoS alerts

### 2. SQL Injection Test
```bash
# Using curl to simulate SQL injection
curl "http://target.com/login.php?username=admin' OR '1'='1&password=anything"

# Using SQLMap
sqlmap -u "http://target.com/login.php" --forms
```

Expected Behavior:
- Rule engine detects SQL injection patterns
- RL agent learns to block similar patterns
- Log panel shows SQL injection alerts
- Statistics show blocked attempts

### 3. Port Scanning
```bash
# Using nmap
nmap -sS -p 1-1000 192.168.1.100

# Using hping3
hping3 -S -p ++1 192.168.1.100
```

Expected Behavior:
- Multiple connection attempts detected
- RL agent identifies scanning pattern
- Log panel shows port scan alerts
- Statistics show blocked ports

### 4. Snort Rule Testing
1. Add custom rule to `rules/snort.rules`:
```
alert tcp any any -> any 80 (msg:"Test Rule"; content:"test"; sid:1000001;)
```

2. Generate test traffic:
```bash
curl "http://target.com/test"
```

Expected Behavior:
- Rule engine detects matching traffic
- Alert generated in log panel
- RL agent learns from rule matches

## 📊 Monitoring

### Packet Display
- Shows detailed packet information
- Color-coded by protocol
- Real-time updates

### Statistics
- Traffic patterns
- Protocol distribution
- RL performance metrics
- Accuracy over time

### Logs
- Security events
- Severity levels
- Timestamp and details
- Export capability

### RL Decisions
- Real-time decisions
- Confidence levels
- Learning progress
- Performance metrics

## 🏗️ Project Structure

```
network-ids-rl/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/
│   │   │       └── example/
│   │   │           ├── capture/     # Packet capture implementation
│   │   │           ├── detection/   # Rule-based detection
│   │   │           ├── gui/         # User interface components
│   │   │           └── rl/          # Reinforcement Learning implementation
│   │   └── resources/
│   │       └── icons/              # GUI icons
├── logs/                           # Log files directory
├── rules/                          # Snort rules directory
├── pom.xml                         # Maven configuration
└── README.md                       # This file
```

## 🛠️ Development

### Building from Source
```bash
mvn clean package
```

### Running Tests
```bash
mvn test
```

### Adding New Features
1. Follow the existing package structure
2. Implement new components in appropriate packages
3. Update the GUI to include new features
4. Add appropriate tests

## 🔧 Troubleshooting

### Common Issues
1. **Permission Denied**
   - Ensure you have administrator/root privileges
   - Check network interface permissions
   - Run as administrator/root

2. **No Packets Captured**
   - Verify network interface selection
   - Check interface is in promiscuous mode
   - Ensure no firewall is blocking capture
   - Try different network interfaces

3. **RL Model Not Loading**
   - Verify model file exists
   - Check model compatibility
   - Ensure correct file permissions
   - Check model version compatibility

### Logs
- Check `logs/ids_YYYY-MM-DD.log` for detailed error information
- Monitor system logs for permission issues
- Export logs for analysis

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Snort for rule-based detection
- Pcap4J for packet capture
- Various open-source RL libraries
- Community contributors

## 📞 Contact

For support or questions, please open an issue in the GitHub repository.

## 📚 Additional Resources

- [Snort Documentation](https://www.snort.org/documents)
- [Pcap4J Documentation](https://www.pcap4j.org/)
- [Reinforcement Learning Tutorial](https://www.tensorflow.org/agents/tutorials/intro_rl)
- [Network Security Best Practices](https://www.cisa.gov/cybersecurity)
