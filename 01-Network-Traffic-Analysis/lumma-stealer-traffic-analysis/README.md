# Lumma Stealer Traffic Analysis

## Overview

This case study documents the analysis of a packet capture associated with an Emerging Threats alert for **Lumma Stealer Victim Fingerprinting Activity**.

The investigation focused on identifying the affected internal host, attributing the activity to a specific Windows user, identifying the associated domain, and analysing the HTTP traffic used for victim fingerprinting.

The analysis was performed using Wireshark and focused on correlating network-layer, Windows authentication, and HTTP evidence.

## Investigation Objectives

- Identify the infected internal host
- Determine the host MAC address and hostname
- Identify the associated Windows username and full name
- Identify the domain associated with the Lumma Stealer alert
- Analyse the HTTP fingerprinting activity
- Correlate the observed traffic with the IDS alert

## Tools Used

- Wireshark
- Emerging Threats IDS signatures
- TCP/IP protocol analysis
- Windows network protocol analysis
## Investigation Context

A Security Operations Center (SOC) alert identified network activity matching the Emerging Threats signature:

**ET MALWARE Lumma Stealer Victim Fingerprinting Activity**

The alert referenced traffic involving the external IP address `153.92.1.49` over TCP port `80`.

The provided packet capture contained traffic from the internal network `10.1.21.0/24`. The first objective was to determine which internal system communicated with the known external indicator.

## Initial IOC Pivot

The investigation began by filtering the packet capture using the known IP address and port:

```wireshark
ip.addr == 153.92.1.49 && tcp.port == 80
