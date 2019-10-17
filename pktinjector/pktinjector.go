// Package pktinjector injects specific packets.
package pktinjector

import (
	"flag"
	"math"
	"net"
	"strings"
	"sync"

	"github.com/apex/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/rtx"
)

var (
	networkInterface = flag.String("pktinjector.network-interface", "",
		"interface where to possibly inject packets")
	keywords        flagx.StringArray
	nxdomains       flagx.StringArray
	redirectDomains flagx.StringArray
)

func init() {
	flag.Var(&keywords, "pktinjector.reset-if-match",
		"Inject RST segment if TCP segment matches <value>")
	flag.Var(&nxdomains, "pktinjector.nxdomain-if-match",
		"Inject NXDOMAIN response if query name matches <value>")
	flag.Var(&redirectDomains, "pktinjector.redirect-if-match",
		"Inject 127.0.0.1 response if query name matches <value>")
}

func newPcapHandleWithFilter(filter string) *pcap.Handle {
	inactive, err := pcap.NewInactiveHandle(*networkInterface)
	rtx.Must(err, "pcap.NewInactiveHandle failed")
	defer inactive.CleanUp()
	err = inactive.SetImmediateMode(true)
	rtx.Must(err, "inactive.SetImmediateMode failed")
	err = inactive.SetPromisc(false)
	rtx.Must(err, "inactive.SetPromisc failed")
	err = inactive.SetSnapLen(256)
	rtx.Must(err, "inactive.SetSnapLen failed")
	handle, err := inactive.Activate()
	rtx.Must(err, "inactive.Activate failed")
	err = handle.SetBPFFilter(filter)
	rtx.Must(err, "handle.SetBPFFilter failed")
	return handle
}

func censorWithNXDOMAIN(
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

func censorWithLocalhost(
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
	dns.ResponseCode = layers.DNSResponseCodeNoErr
	dns.ANCount = 1
	dns.Answers = []layers.DNSResourceRecord{
		layers.DNSResourceRecord{
			Name:  dns.Questions[0].Name,
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
			TTL:   math.MaxInt32,
			IP:    net.IPv4(127, 0, 0, 1),
		},
	}

	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, eth, ip, udp, dns)
	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.WithError(err).Warn("handle.WritePacketData failed")
	}
}

func filterDNS(wg *sync.WaitGroup) {
	defer wg.Done()
	handle := newPcapHandleWithFilter("ip and udp and dst port 53")
	defer handle.Close()
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		dnslayer := packet.Layer(layers.LayerTypeDNS)
		if dnslayer == nil {
			continue
		}
		dns := dnslayer.(*layers.DNS)
		for _, question := range dns.Questions {
			name := string(question.Name)
			for _, domain := range nxdomains {
				if strings.Contains(name, domain) {
					log.Infof("pktinjector: will NXDOMAIN-inject: %s", name)
					censorWithNXDOMAIN(handle, packet, dns)
					break
				}
			}
			for _, domain := range redirectDomains {
				if strings.Contains(name, domain) {
					log.Infof("pktinjector: will 127.0.0.1-redirect: %s", name)
					censorWithLocalhost(handle, packet, dns)
					break
				}
			}
		}
	}
}

func censorWithRST(
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

func filterTCP(wg *sync.WaitGroup) {
	defer wg.Done()
	handle := newPcapHandleWithFilter(
		"ip and tcp and (dst port 80 or dst port 443)",
	)
	defer handle.Close()
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		tcplayer := packet.Layer(layers.LayerTypeTCP)
		if tcplayer == nil {
			continue
		}
		tcp := tcplayer.(*layers.TCP)
		payload := string(tcp.LayerPayload())
		for _, keyword := range keywords {
			if strings.Contains(payload, keyword) {
				log.Infof("pktinjector: will RST-censor: %s", keyword)
				censorWithRST(handle, packet, tcp)
				break
			}
		}
	}
}

// Start starts the injector
func Start() {
	if *networkInterface == "" {
		log.Warn("injector: no interface specified")
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go filterDNS(&wg)
	go filterTCP(&wg)
	wg.Wait()
}
