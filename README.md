# SimSpace_Cyber_Range_School_Project
Overview
This project focuses on analyzing network traffic from a collection of 15 PCAP files within a SimSpace Cyber Range virtual machine environment. The goal was to identify and investigate malicious activity using Wireshark, NetworkMiner, and Snort. The analysis revealed multiple cybersecurity threats and vulnerabilities, providing valuable insights into real-world attack vectors and network forensics techniques.

1. Tools Used
Wireshark
* Open-source network protocol analyzer.
* Used for inspecting packets, identifying malicious patterns, and detecting anomalies.
NetworkMiner
* Passive network forensic analysis tool.
* Extracts files, credentials, and metadata from PCAP files.
Snort
* Open-source Intrusion Detection System (IDS).
* Used to detect and alert on suspicious network activity.

2. Identified Threats & Vulnerabilities
During the analysis, the following security vulnerabilities and attack patterns were identified:
1. EternalBlue Exploit
* Exploits SMBv1 vulnerability (CVE-2017-0144).
* Used for remote code execution and ransomware deployment.
* Detected through anomalous SMB traffic patterns.
      
2. ARP Poisoning (Man-in-the-Middle Attack)
* Alters ARP tables to intercept network traffic.
* Used to eavesdrop on sensitive data or redirect traffic.
* Detected through abnormal ARP request/reply behavior.

3. ICMP Flood (Denial-of-Service Attack)
* Overwhelms a target system with excessive ICMP Echo Requests (ping flood).
* Causes network performance degradation.
* Identified via excessive ICMP traffic volume.
  
4. Broken TCP ACK (TCP Injection Attack)
* Manipulates TCP ACK flags to disrupt communication.
* Can be used for session hijacking or connection termination.
* Identified through irregular TCP sequences and retransmissions.

3. Methodology
Step 1: Setting Up the Cyber Range VM
* PCAP files were transferred to a virtual machine within SimSpace Cyber Range.
* Security analysis tools (Wireshark, NetworkMiner, Snort) were installed.
    
Step 2: Traffic Analysis
* Wireshark: Used to analyze packet behavior and extract indicators of compromise (IoCs).
* NetworkMiner: Extracted files and metadata to identify malware signatures.
* Snort: Applied predefined rules to detect known attack patterns.
    
Step 3: Identifying Malicious Traffic
* Inspected suspicious IP addresses, unusual protocols, and malformed packets.
* Detected attack patterns by cross-referencing with threat intelligence databases.
    
Step 4: Reporting & Documentation
* Findings were documented, including attack timestamps, affected hosts, and potential mitigations.
* Suggested security measures to prevent and mitigate similar attacks in real-world environments.

4. Key Takeaways
* Hands-on experience with network forensics and cybersecurity tools.
* Identification and mitigation of common network-based attacks.
* Understanding of how attackers exploit network vulnerabilities.
* Importance of intrusion detection and log analysis in cybersecurity.

5. Future Enhancements
* Automate PCAP analysis using Python & Scapy.
* Implement SIEM (Security Information & Event Management) integration.
* Expand detection capabilities with custom Snort rules.
* Conduct real-time threat hunting using ELK Stack (Elasticsearch, Logstash, Kibana).


