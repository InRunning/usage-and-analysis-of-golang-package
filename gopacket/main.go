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

	reader, err := pcapgo.NewNgReader(pcapFile, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		log.Fatal("can't open reader, error: ", err)
		return
	}
	packetSource := gopacket.NewPacketSource(reader, layers.LinkTypeEthernet)
	fmt.Println("packet length: ", len(packetSource.Packets()))
	for packet := range packetSource.Packets() {
		printPacketInfo(packet)
		break
	}
}

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
