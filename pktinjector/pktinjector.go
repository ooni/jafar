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
	"github.com/miekg/dns"
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

func reflectudp(handle *pcap.Handle, incoming gopacket.Packet, payload []byte) {
	ethernet, ok := incoming.LinkLayer().(*layers.Ethernet)
	if !ok {
		log.Warn("original packet was not ethernet")
		return
	}
	ipv4, ok := incoming.NetworkLayer().(*layers.IPv4)
	if !ok {
		log.Warn("original packet was not IPv4")
		return
	}
	udp, ok := incoming.TransportLayer().(*layers.UDP)
	if !ok {
		log.Warn("original packet was not UDP")
		return
	}
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, &layers.Ethernet{
		SrcMAC: ethernet.DstMAC,
		DstMAC: ethernet.SrcMAC,
	}, &layers.IPv4{
		SrcIP: ipv4.DstIP,
		DstIP: ipv4.SrcIP,
	}, &layers.UDP{
		SrcPort: udp.DstPort,
		DstPort: udp.SrcPort,
	}, gopacket.Payload(payload))
	// TODO(bassosimone): this does not seem to work on macOS?
	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.WithError(err).Warn("handle.WritePacketData failed")
	}
}

func censordomain(handle *pcap.Handle, packet gopacket.Packet, query *dns.Msg) {
	reply := new(dns.Msg)
	reply.SetRcode(query, dns.RcodeNameError)
	payload, err := reply.Pack()
	if err != nil {
		log.WithError(err).Warn("cannot serialize DNS payload")
		return
	}
	reflectudp(handle, packet, payload)
}

func processdns(handle *pcap.Handle, packet gopacket.Packet, payload []byte) {
	query := new(dns.Msg)
	if err := query.Unpack(payload); err != nil {
		log.WithError(err).Warn("cannot parse DNS payload")
		return
	}
	if query.MsgHdr.Response {
		return
	}
	for _, question := range query.Question {
		for _, domain := range domains {
			if strings.Contains(question.Name, domain) {
				log.Infof("need to DNS censor: %s", question.Name)
				censordomain(handle, packet, query)
				return
			}
		}
	}
}

func process(handle *pcap.Handle, packet gopacket.Packet) {
	dnslayer := packet.Layer(layers.LayerTypeDNS)
	if dnslayer != nil {
		processdns(handle, packet, dnslayer.LayerContents())
	}
}

// Start starts the injector
func Start() {
	if *networkInterface == "" {
		log.Warn("injector: no interface specified")
		return
	}
	handle, err := pcap.OpenLive(*networkInterface, 1600, true, pcap.BlockForever)
	rtx.Must(err, "pcap.OpenLive failed")
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		process(handle, packet)
	}
}
