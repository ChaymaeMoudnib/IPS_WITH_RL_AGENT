# 🛡️ Network Intrusion Detection & Prevention System (IDPS) with Reinforcement Learning

A modern, hybrid Intrusion Detection and Prevention System that combines traditional Snort-style rule-based detection with Reinforcement Learning (RL) for adaptive, intelligent network security.  
Monitor, detect, and respond to threats in real time, with a user-friendly GUI and advanced alerting.


## ✨ Features

### Core Functionality
- **Real-time packet capture** (using Pcap4J)
- **Rule-based detection** (Snort rules, custom rules)
- **Reinforcement Learning agent** for adaptive threat response
- **Multi-threaded** processing for high performance
- **Comprehensive statistics**: protocol, traffic, alerts, RL accuracy

### Security & Detection
- Detects:  
  - XSS attacks  
  - SQL injection  
  - Port scans    
  - Custom Snort rules (ICMP, TCP, UDP, etc.)
- **Anomaly detection** (heuristics + RL)
- **Active/Passive blocking** (configurable)
- **Alert severity**: CRITICAL, HIGH, MEDIUM, LOW

### GUI Highlights
- **Control Panel**: Start/stop capture, select interface, toggle RL
- **Simulation Panel**: Simulate XSS, SQLi, Port Scan, Snort rule tests
- **Packet Display**: Live packet info
- **Statistics Panel**: Traffic, RL stats, accuracy
- **Log Panel**: Alerts, events, exportable logs
- **RL Decisions Panel**: RL agent actions, confidence, learning

### Alerting & Logging
- **Visual alerts** in GUI (color-coded, icons)
- **Email notifications** for HIGH/CRITICAL alerts (configurable)
- **Persistent log files** (`logs/ids_YYYY-MM-DD.log`)
- **Export logs** for analysis

### Extensibility
- Add new rules in `rules/snort.rules`
- Plug in new RL models (`trained_model.rl`)
- Modular codebase for easy feature addition

---

## 📋 Prerequisites

- Java 17+
- Maven 3.6+
- Admin/root privileges for packet capture
- Network interface with promiscuous mode

---

## 📦 Dependencies

See `pom.xml` for all dependencies.  


---

## 🚀 Installation

```bash
git clone https://github.com/ChaymaeMoudnib/IPS_WITH_RL_AGENT
cd IPS_WITH_RL_AGENT
mvn clean install
```

---

## ⚙️ Configuration

### Network Interface
- Windows: `\Device\NPF_{GUID}`
- Linux: `eth0`, `wlan0`
- macOS: `en0`, `en1`

### Rules
- Place Snort rules in `rules/snort.rules`
- Use standard Snort syntax (see [Snort Docs](https://www.snort.org/documents))

### RL Model
- Place your RL model as `trained_model.rl` in the project root

### Email Alerts
- Configure via GUI: "Configure Email Alerts" button
- Requires Gmail address and App Password (see help in dialog)

---

## 🤝 Contributing

- Fork, branch, commit, PR!

---

## 📞 Contact

Open an issue on GitHub for support.

---

## 📚 Resources

- [Snort Documentation](https://www.snort.org/documents)
- [Pcap4J Documentation](https://www.pcap4j.org/)
- [Reinforcement Learning Tutorial](https://www.tensorflow.org/agents/tutorials/intro_rl)
- [Network Security Best Practices](https://www.cisa.gov/cybersecurity)

