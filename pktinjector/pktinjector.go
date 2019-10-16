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
	domains flagx.StringArray
)

func init() {
	flag.Var(&domains, "dns-injection-for",
		"Domain to perform DNS injection for")
}

func censordomain(handle *pcap.Handle, packet gopacket.Packet) {
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

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		log.Warn("pktinjector: not a DNS packet")
		return
	}
	dns := dnsLayer.(*layers.DNS)
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
			for _, domain := range domains {
				if strings.Contains(string(question.Name), domain) {
					log.Infof("pktinjector: will DNS-censor: %s", string(question.Name))
					censordomain(handle, packet)
					return
				}
			}
		}
	}
}

func process(handle *pcap.Handle, packet gopacket.Packet) {
	dnslayer := packet.Layer(layers.LayerTypeDNS)
	if dnslayer != nil {
		processdns(handle, packet, dnslayer.(*layers.DNS))
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
