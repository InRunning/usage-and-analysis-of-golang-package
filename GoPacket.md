# GoPacket

[TOC]

## 1. Usage of GoPacket

### 1.1 Introduction of GoPacket

GoPacket is a library which can be used to decode network packet.

### 1.2 demo of gopacket

First, we need to get a network packet to be analyze by GoPacket, you can use [wireshark](https://www.wireshark.org/) to capture your local network packet, or you can use the [network packet](https://github.com/InRunning/usage-and-analysis-of-golang-package/blob/main/gopacket/network%20packet.pcapng) I provided to analyze.

Second, we need to realize what we need to analyze, just look at the screenshot below, the network packet we capture is sending the same UDP packet repetitively.


![UDP network packet](https://github.com/InRunning/usage-and-analysis-of-golang-package/blob/main/gopacket/network%20packet%20screenshot.png?raw=true)

If we want to get source port and destination port of udp, we can write a demo main file to get these with gopacket package.
Below is source code:
