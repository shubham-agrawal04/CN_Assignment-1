# Packet Sniffer and Network Analysis

## Overview
This project is a packet sniffer implemented in Python using raw sockets. It captures network packets and performs real-time analysis. The project also extends into analyzing PCAP files for extracting network insights.

## Team Members
- **Shubham Agrawal** (22110249)
- **Vraj Shah** (22110292)

## How to Run the Code

### 1. Clone the Repository
```sh
git clone https://github.com/shubham-agrawal04/CN_Assignment-1.git
cd CN_Assignment-1
```

### 2. Install Dependencies
Ensure Python is installed along with the required libraries.

```sh
pip install -r requirements.txt  # If a requirements.txt file is available
```

### 3. Install PCAP File
Ensure that `2.pcap` is available in the repository directory.  
Download it from: [Google Drive Link](https://drive.google.com/drive/folders/1n84jGddZ38fDjy9jKH3qw3J_H0SaKThu)

### 4. Set Up Your Environment
- Configure Ethernet between two machines correctly.
- Use the `eth0` port of your WSL instance in Windows.
- Disable Wi-Fi to avoid interference with Ethernet-based communication.

### 5. Run the Packet Sniffer Script
```sh
sudo python3 temp2.py -i [interface-name]
```

### 6. Run `tcpreplay`
On the machine where `tcpreplay` is set up, run:
```sh
sudo tcpreplay -i [interface-name] --pps=[speed] 2.pcap
```
For same-machine testing, use `pps <= 14000`.  
For different machines, adjust `pps` accordingly.

### 7. Check the Results
Once the script completes execution, the results will be available.

## Additional Information
For further details, visit the full report or the repository:
[GitHub Repository](https://github.com/shubham-agrawal04/CN_Assignment-1)
