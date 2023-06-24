# GoPacket

[TOC]

## 1. Usage of GoPacket

### 1.1 Introduction of GoPacket

GoPacket is a library which can be used to decode network packet.

### 1.2 demo of gopacket

First, we need to get a network packet to be analyze by GoPacket, you can use [wireshark](https://www.wireshark.org/) to capture your local network packet, or you can use the [network packet](https://github.com/InRunning/usage-and-analysis-of-golang-package/blob/main/gopacket/network%20packet.pcapng) I provided to analyze.

Second, we need to realize what we need to analyze, just look at the screenshot below, the network packet we capture is sending the same UDP packet repetitively.

![UDP network packet](https://github.com/InRunning/usage-and-analysis-of-golang-package/blob/main/gopacket/network%20packet%20screenshot.png?raw=true)

If we want to see the packet content in the pcapng file, we need to generate a [packetsource](https://pkg.go.dev/github.com/google/gopacket#hdr-Reading_Packets_From_A_Source) of gopacket. To generate packetsource, we need to get reader of pcapng file first. Below is the source code.

```go
package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"log"
	"os"
)

func main() {
	pcapFileName := "gopacket/network-packet.pcapng"
	pcapFile, err := os.Open(pcapFileName)
	if err != nil {
		log.Fatal("can't open file, error: ", err)
		return
	}
	defer func(pcapFile *os.File) {
		err := pcapFile.Close()
		if err != nil {
			log.Fatal("can't close file, error: ", err)
			return
		}
	}(pcapFile)

	// get pcapng file reader
	reader, err := pcapgo.NewNgReader(pcapFile, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		log.Fatal("can't open reader, error: ", err)
		return
	}
	// use reader to generate packetsource
	packetSource := gopacket.NewPacketSource(reader, layers.LinkTypeEthernet)
	fmt.Println("packet length: ", len(packetSource.Packets()))
	for packet := range packetSource.Packets() {
		printPacketInfo(packet)
		break
	}
}
```

In the above code, we use pcapgo.NewNgReader to generate the reader of pcapgo file, then we use gopacket.NewPacketSource to generate packetSource. After that, we can use range to traversal all the packets one by one in pcapng file. 

For simplicity, we only printed the first packet in the above code, below is printPacketInfo() function.

```go
func printPacketInfo(packet gopacket.Packet) {
	// Let's see if the packet is an ethernet packet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		fmt.Println("Ethernet layer detected.")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
		fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
		// Ethernet type is typically IPv4 but could be ARP or other
		fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
		fmt.Println()
	}

	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol: ", ip.Protocol)
		fmt.Println()
	}

	// Let's see if the packet is TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)

		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
		fmt.Println("Sequence number: ", tcp.Seq)
		fmt.Println()
	}

	// Let's see if the packet is UDP
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		fmt.Println("UDP layer detected.")
		udp, _ := udpLayer.(*layers.UDP)

		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		fmt.Printf("From port %d to %d\n", udp.SrcPort, udp.DstPort)
	}

	// Iterate over all layers, printing out each layer type
	fmt.Println("All packet layers:")
	for _, layer := range packet.Layers() {
		fmt.Println("- ", layer.LayerType())
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
	os.Exit(1)
}
```

Below is the output of above code:

```bash
packet length:  0
Ethernet layer detected.           
Source MAC:  00:15:5d:93:0b:fd     
Destination MAC:  ff:ff:ff:ff:ff:ff
Ethernet type:  IPv4               
                                   
IPv4 layer detected.               
From 172.17.192.1 to 172.17.207.255
Protocol:  UDP                     
                                   
UDP layer detected.                
From port 2008 to 2008             
All packet layers:                 
-  Ethernet                        
-  IPv4                            
-  UDP                             
-  Payload  
```
