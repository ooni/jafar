// Package pktinjector injects specific packets.
package pktinjector

import (
	"flag"
	"strings"

	"github.com/apex/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/rtx"
)

var (
	networkInterface = flag.String("network-interface", "",
		"interface where to inject packets")
	domains  flagx.StringArray
	keywords flagx.StringArray
)

func init() {
	flag.Var(&domains, "dns-injection-for",
		"Domain to perform DNS injection for")
	flag.Var(&keywords, "rst-injection-for",
		"Keywords to perform RST injection for")
}

func censordomain(
	handle *pcap.Handle, packet gopacket.Packet, dns *layers.DNS,
) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		log.Warn("pktinjector: not an ethernet packet")
		return
	}
	eth := ethLayer.(*layers.Ethernet)
	srcMAC := eth.SrcMAC
	eth.SrcMAC = eth.DstMAC
	eth.DstMAC = srcMAC

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		log.Warn("pktinjector: not an IPv4 packet")
		return
	}
	ip := ipLayer.(*layers.IPv4)
	srcIP := ip.SrcIP
	ip.SrcIP = ip.DstIP
	ip.DstIP = srcIP

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		log.Warn("pktinjector: not an UDP packet")
		return
	}
	udp := udpLayer.(*layers.UDP)
	srcPort := udp.SrcPort
	udp.SrcPort = udp.DstPort
	udp.DstPort = srcPort
	udp.SetNetworkLayerForChecksum(ip)

	dns.QR = true
	dns.RA = true
	dns.RD = true
	dns.ResponseCode = layers.DNSResponseCodeNXDomain

	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, eth, ip, udp, dns)
	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.WithError(err).Warn("handle.WritePacketData failed")
	}
}

func processdns(
	handle *pcap.Handle, packet gopacket.Packet, dns *layers.DNS,
) {
	if dns.QR == false {
		for _, question := range dns.Questions {
			name := string(question.Name)
			for _, domain := range domains {
				if strings.Contains(name, domain) {
					log.Infof("pktinjector: will DNS-censor: %s", name)
					censordomain(handle, packet, dns)
					return
				}
			}
		}
	}
}

func censortcp(
	handle *pcap.Handle, packet gopacket.Packet, tcp *layers.TCP,
) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		log.Warn("pktinjector: not an ethernet packet")
		return
	}
	eth := ethLayer.(*layers.Ethernet)
	srcMAC := eth.SrcMAC
	eth.SrcMAC = eth.DstMAC
	eth.DstMAC = srcMAC

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		log.Warn("pktinjector: not an IPv4 packet")
		return
	}
	ip := ipLayer.(*layers.IPv4)
	srcIP := ip.SrcIP
	ip.SrcIP = ip.DstIP
	ip.DstIP = srcIP

	srcPort := tcp.SrcPort
	tcp.SrcPort = tcp.DstPort
	tcp.DstPort = srcPort
	tcp.SetNetworkLayerForChecksum(ip)
	seq := tcp.Seq
	tcp.Seq = tcp.Ack
	tcp.Ack = seq
	tcp.DataOffset = 0
	tcp.FIN = false
	tcp.SYN = false
	tcp.RST = true
	tcp.PSH = false
	tcp.ACK = false
	tcp.URG = false
	tcp.ECE = false
	tcp.CWR = false
	tcp.NS = false
	tcp.Window = 0
	tcp.Checksum = 0
	tcp.Urgent = 0
	tcp.Options = nil
	tcp.Padding = nil

	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, eth, ip, tcp)
	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.WithError(err).Warn("handle.WritePacketData failed")
	}
}

func processtcp(
	handle *pcap.Handle, packet gopacket.Packet, tcp *layers.TCP,
) {
	if tcp.DstPort == 80 || tcp.DstPort == 443 {
		payload := string(tcp.LayerPayload())
		for _, keyword := range keywords {
			if strings.Contains(payload, keyword) {
				log.Infof("pktinjector: will RST-censor: %s", keyword)
				censortcp(handle, packet, tcp)
				return
			}
		}
	}
}

func process(handle *pcap.Handle, packet gopacket.Packet) {
	dnslayer := packet.Layer(layers.LayerTypeDNS)
	if dnslayer != nil {
		processdns(handle, packet, dnslayer.(*layers.DNS))
	}
	tcplayer := packet.Layer(layers.LayerTypeTCP)
	if tcplayer != nil {
		processtcp(handle, packet, tcplayer.(*layers.TCP))
	}
}

// Start starts the injector
func Start() {
	if *networkInterface == "" {
		log.Warn("injector: no interface specified")
		return
	}
	handle, err := pcap.OpenLive(*networkInterface, 1600, false, pcap.BlockForever)
	rtx.Must(err, "pcap.OpenLive failed")
	defer handle.Close()
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		process(handle, packet)
	}
}
