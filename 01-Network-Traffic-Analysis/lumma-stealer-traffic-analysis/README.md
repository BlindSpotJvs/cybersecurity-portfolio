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
