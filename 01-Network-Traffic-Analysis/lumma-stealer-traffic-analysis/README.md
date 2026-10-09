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

### Evidence 04 — Account Attribution via Kerberos

Kerberos authentication traffic between the host of interest and the domain controller was analysed to identify the Windows account associated with the system.

An Authentication Service Request (AS-REQ) originating from `10.1.21.58` to the domain controller `10.1.21.2` contained the Kerberos client principal:

`gwyatt`

The request was associated with the `WIN11OFFICE` realm and also contained the previously identified hostname `DESKTOP-ES9F3ML`, further correlating the host and account information.

**Finding:** The Windows account associated with the host was `gwyatt`.

![Kerberos account attribution](images/04-kerberos-account-attribution.png)

### Evidence 05 — Full Name Attribution via SAMR

After identifying the Windows account `gwyatt`, Security Account Manager Remote (SAMR) traffic was analysed to resolve the account to a full user identity.

A `QueryUserInfo` response from the domain controller `10.1.21.2` contained:

- Account Name: `gwyatt`
- Full Name: `Gabriel Wyatt`

This completed the correlation between the affected system and the associated Windows user account.

**Finding:** The account `gwyatt` was associated with the user `Gabriel Wyatt`.

![SAMR full name attribution](images/05-samr-full-name-attribution.png)

### Evidence 06 — C2 Domain Identification

HTTP traffic associated with the external IOC was analysed to identify the domain used during the suspicious communication.

Requests from `10.1.21.58` to `153.92.1.49` contained the HTTP Host header:

`whitepepper.su`

The same traffic also included requests to the `/api/set_agent` endpoint with client-identifying parameters, providing a direct relationship between the external IP address, domain, and observed Lumma-associated activity.

**Finding:** The domain associated with the suspicious traffic to `153.92.1.49` was `whitepepper.su`.

![C2 domain identification](images/06-c2-domain-identification.png)

### Evidence 07 — Victim Fingerprinting Payload

The suspicious HTTP POST traffic was examined to determine what information the affected host transmitted to the remote infrastructure.

A POST request from `10.1.21.58` to `whitepepper.su` used the endpoint `/api/set_agent` and transmitted approximately `7,975` bytes of URL-encoded data.

The submitted form contained multiple categories of client information, including:

- System and browser information
- WebGL and graphics information
- Canvas fingerprint data
- Network characteristics
- Screen resolution and color depth
- Hardware characteristics
- Language settings
- Installed/common fonts
- WebRTC information
- Audio characteristics
- Browser capabilities and plugins

The traffic also included a browser-style User-Agent identifying Microsoft Edge, consistent with the `agent=Edge` parameter present in the request.

**Finding:** The host transmitted a detailed browser and system fingerprint to the Lumma-associated infrastructure, consistent with the victim fingerprinting behavior described by the IDS alert.

![Victim fingerprinting payload](images/07-victim-fingerprinting-payload.png)

### Evidence 08 — Fingerprinting Script Analysis

The HTTP response delivered by `153.92.1.49` contained JavaScript designed to collect detailed characteristics from the client system.

The script queried multiple browser and system properties, including:

- Operating system and browser information
- Language and browser settings
- CPU concurrency and device memory
- WebGL vendor and renderer information
- Canvas rendering characteristics
- Screen and display properties
- Network characteristics
- WebRTC information
- Audio capabilities
- Browser plugins and additional client features

![Fingerprinting script collecting client characteristics](images/08a-fingerprinting-script-collection.png)

The collected values were then assembled into a `fingerprint` object. Individual data categories were serialized using `JSON.stringify()` and converted into URL-encoded form data using `URLSearchParams`.

The script subsequently transmitted the fingerprint using an HTTP POST request with the content type:

`application/x-www-form-urlencoded`

![Fingerprint assembly and POST submission](images/08b-fingerprinting-script-post.png)

This reconstructed the full fingerprinting workflow observed in the packet capture:

```text
Remote server
      ↓
delivers JavaScript
      ↓
collects client characteristics
      ↓
builds fingerprint object
      ↓
URL-encodes the data
      ↓
HTTP POST to remote infrastructure
```

**Finding:** The remote infrastructure delivered browser-based fingerprinting code that collected detailed client characteristics and transmitted the resulting fingerprint back to the server.
