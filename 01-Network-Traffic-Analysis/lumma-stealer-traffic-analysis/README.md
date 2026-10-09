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

## Initial IOC Pivot

The investigation began by filtering the packet capture using the known IP address and port:

```wireshark
ip.addr == 153.92.1.49 && tcp.port == 80
```

The resulting traffic showed repeated communication between `153.92.1.49` and the internal host `10.1.21.58`.

**Finding:** `10.1.21.58` was identified as the primary host of interest.

### Evidence 01 — IOC Pivot and Internal Host Identification

The known external IOC `153.92.1.49:80` was used as the starting point for the investigation. Filtering the packet capture revealed repeated bidirectional communication with the internal host `10.1.21.58`.

![IOC pivot identifying the internal host](images/01-initial-ioc-internal-host.png)

### Evidence 02 — MAC Address Attribution

After identifying `10.1.21.58` as the primary host of interest, Ethernet-layer information was examined to associate the IP address with its network interface.

The source MAC address observed for traffic originating from `10.1.21.58` was:

`00:21:5d:c8:0e:f2`

The destination MAC address belonged to the local gateway, while the Layer 3 destination remained the external IP `153.92.1.49`. This is consistent with normal routed traffic, where Ethernet identifies the next local hop and IP identifies the final network destination.

**Finding:** `10.1.21.58` was associated with MAC address `00:21:5d:c8:0e:f2`.

![MAC address attribution](images/02-mac-address-attribution.png)

### Evidence 03 — Hostname Identification

Local Windows name-resolution traffic was examined to determine the hostname associated with the identified system.

The host `10.1.21.58`, associated with MAC address `00:21:5d:c8:0e:f2`, generated NetBIOS Name Service registration traffic containing:

`DESKTOP-ES9F3ML`

The same hostname was also observed in LLMNR traffic, providing additional correlation between the IP address, network interface, and Windows host identity.

**Finding:** The hostname associated with `10.1.21.58` was `DESKTOP-ES9F3ML`.

![Hostname identification using NBNS and LLMNR](images/03-hostname-identification.png)
