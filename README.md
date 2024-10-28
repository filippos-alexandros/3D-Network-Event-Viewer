# 3D Visualization of Network Attacks and Defenses - An Interactive Representation of Cybersecurity Events

1. The aim of this project is to create an application that extracts network traffic data from a PCAP file, and visualises the flow of information, cyber-attacks and defense mechanisms in an intuitive 3D format. 


## Getting Started

1. Clone this repository to your local machine.

2. Navigate to the project directory.

3. Install the required dependencies using pip:
    pip install -r requirements.txt

After installing the dependencies, you can run the application by executing the main script:
python main.py

Sample PCAP files used during development have been included in the Samples file.
IOT-23 dataset captures were also used, but no included in the file due to their massive size.
As they are huge, if tested with these please use CTU-Honeypot-Capture-5-1: 2018.09.21-capture.pcap to avoid massive analysis times. Can be downloaded below:
https://www.stratosphereips.org/datasets-iot23

smallFlows.pcap is a regular network traffic sample.
SynFlood Sample.pcap is a DDoS SYN Flood.
amp.TCP.syn.optioanllyACK.optionallysamePort.pcap is a combination Dos/DDos SYN Flood.
amp.TCP.reflection.SYNACK.pcap is a DDoS SYN + ICMP flood.
SYN.pcap is a DoS SYN flood.
SNMPv3.pcap is a SNMP sample for defense mechanisms showing that SNMP currently is displayed under UDP