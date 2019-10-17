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
	blackholeWithDNSInjection flagx.StringArray
	blockWithDNSInjection     flagx.StringArray
	blockWithRSTInjection     flagx.StringArray
	hijackWithDNSInjection    flagx.StringArray
	interfaces                flagx.StringArray
)

func init() {
	flag.Var(
		&blackholeWithDNSInjection, "pktinjector-dns-blackhole",
		"Use DNS injection to blackhole DNS queries containing <value>",
	)
	flag.Var(
		&blockWithDNSInjection, "pktinjector-dns-block",
		"Block DNS resolution by injecting a NXDOMAIN if query contains <value>",
	)
	flag.Var(
		&blockWithRSTInjection, "pktinjector-rst",
		"Block TCP stream containing <value> using RST injection",
	)
	flag.Var(
		&hijackWithDNSInjection, "pktinjector-dns-hijack",
		"Use DNS injection to hijack DNS queries containing <value>",
	)
	flag.Var(
		&interfaces, "pktinjector-interface",
		"Apply censorship rules on traffic on interface named <value>",
	)
}

func newPcapHandleWithFilter(ifname, filter string) *pcap.Handle {
	inactive, err := pcap.NewInactiveHandle(ifname)
	rtx.Must(err, "pcap.NewInactiveHandle failed")
	defer inactive.CleanUp()
	err = inactive.SetImmediateMode(true)
	rtx.Must(err, "inactive.SetImmediateMode failed")
	err = inactive.SetPromisc(false)
	rtx.Must(err, "inactive.SetPromisc failed")
	err = inactive.SetSnapLen(512)
	rtx.Must(err, "inactive.SetSnapLen failed")
	handle, err := inactive.Activate()
	rtx.Must(err, "inactive.Activate failed")
	err = handle.SetBPFFilter(filter)
	rtx.Must(err, "handle.SetBPFFilter failed")
	return handle
}

func doCensorWithInjectedReply(
	handle *pcap.Handle, packet gopacket.Packet,
	dns *layers.DNS, redirectTo net.IP,
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
	if redirectTo != nil {
		dns.ResponseCode = layers.DNSResponseCodeNoErr
		dns.ANCount = 1
		dns.Answers = []layers.DNSResourceRecord{
			layers.DNSResourceRecord{
				Name:  dns.Questions[0].Name,
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				TTL:   math.MaxInt32,
				IP:    redirectTo,
			},
		}
	} else {
		dns.ResponseCode = layers.DNSResponseCodeNXDomain
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

func censorDNS(ifname string, wg *sync.WaitGroup) {
	defer wg.Done()
	handle := newPcapHandleWithFilter(ifname, "ip and udp and dst port 53")
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
			for _, pattern := range blockWithDNSInjection {
				if strings.Contains(name, pattern) {
					log.Infof("pktinjector: will NXDOMAIN: %s", name)
					doCensorWithInjectedReply(
						handle, packet, dns, nil,
					)
					break
				}
			}
			for _, pattern := range blackholeWithDNSInjection {
				if strings.Contains(name, pattern) {
					log.Infof("pktinjector: will 127.0.0.2-redirect: %s", name)
					doCensorWithInjectedReply(
						handle, packet, dns, net.IPv4(127, 0, 0, 2),
					)
					break
				}
			}
			for _, pattern := range hijackWithDNSInjection {
				if strings.Contains(name, pattern) {
					log.Infof("pktinjector: will 127.0.0.1-redirect: %s", name)
					doCensorWithInjectedReply(
						handle, packet, dns, net.IPv4(127, 0, 0, 1),
					)
					break
				}
			}
		}
	}
}

func doCensorWithRST(
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

func censorTCPWithFilter(ifname string, wg *sync.WaitGroup, filter string) {
	defer wg.Done()
	handle := newPcapHandleWithFilter(ifname, filter)
	defer handle.Close()
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		tcplayer := packet.Layer(layers.LayerTypeTCP)
		if tcplayer == nil {
			continue
		}
		tcp := tcplayer.(*layers.TCP)
		payload := string(tcp.LayerPayload())
		for _, pattern := range blockWithRSTInjection {
			if strings.Contains(payload, pattern) {
				log.Infof("pktinjector: will RST-censor: %s", pattern)
				doCensorWithRST(handle, packet, tcp)
				break
			}
		}
	}
}

// Start starts the injector
func Start() {
	if interfaces == nil {
		all, err := pcap.FindAllDevs()
		rtx.Must(err, "pcap.FindAllDevs failed")
		for _, iface := range all {
			for _, address := range iface.Addresses {
				ipaddr := address.IP.String()
				if ipaddr != "127.0.0.1" && !strings.Contains(ipaddr, ":") {
					interfaces = append(interfaces, iface.Name)
					break
				}
			}
		}
	}
	var wg sync.WaitGroup
	wg.Add(3 * len(interfaces))
	for _, ifname := range interfaces {
		log.Infof("pktinjector: listening on: %s", ifname)
		go censorDNS(ifname, &wg)
		go censorTCPWithFilter(ifname, &wg, "ip and tcp and dst port 443")
		go censorTCPWithFilter(ifname, &wg, "ip and tcp and dst port 80")
	}
	wg.Wait()
}
