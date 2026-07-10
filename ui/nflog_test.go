//go:build linux

package main

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestParseNflogIPv4TCP(t *testing.T) {
	// 20-byte IPv4 header + 4 bytes of TCP (sport, dport).
	p := make([]byte, 24)
	p[0] = 0x45 // v4, IHL=5 (20 bytes)
	p[9] = 6    // TCP
	copy(p[12:16], net.ParseIP("1.2.3.4").To4())
	copy(p[16:20], net.ParseIP("5.6.7.8").To4())
	binary.BigEndian.PutUint16(p[22:24], 22) // dport 22

	in := uint32(2)
	d := parseNflog("nftgeo-drop:abuse ", p, &in, nil, nil)
	if d.Verdict != "drop" || d.Reason != "abuse" {
		t.Errorf("prefix parse: verdict=%q reason=%q", d.Verdict, d.Reason)
	}
	if d.Src != "1.2.3.4" || d.Dst != "5.6.7.8" {
		t.Errorf("addrs: src=%q dst=%q", d.Src, d.Dst)
	}
	if d.Proto != "TCP" || d.Dport != "22" {
		t.Errorf("l4: proto=%q dport=%q", d.Proto, d.Dport)
	}
	if d.Dir != "ingress" {
		t.Errorf("dir=%q want ingress (indev set, outdev nil)", d.Dir)
	}
}

func TestParseNflogIPv6UDPEgress(t *testing.T) {
	// 40-byte IPv6 header + 4 bytes UDP.
	p := make([]byte, 44)
	p[0] = 0x60 // v6
	p[6] = 17   // UDP next header
	copy(p[8:24], net.ParseIP("2001:db8::1").To16())
	copy(p[24:40], net.ParseIP("2001:db8::2").To16())
	binary.BigEndian.PutUint16(p[42:44], 53) // dport 53

	out := uint32(3)
	d := parseNflog("nftgeo-accept:allow ", p, nil, &out, nil)
	if d.Verdict != "accept" || d.Reason != "allow" {
		t.Errorf("prefix: verdict=%q reason=%q", d.Verdict, d.Reason)
	}
	if d.Src != "2001:db8::1" || d.Dst != "2001:db8::2" {
		t.Errorf("addrs: src=%q dst=%q", d.Src, d.Dst)
	}
	if d.Proto != "UDP" || d.Dport != "53" {
		t.Errorf("l4: proto=%q dport=%q", d.Proto, d.Dport)
	}
	if d.Dir != "egress" {
		t.Errorf("dir=%q want egress (outdev set)", d.Dir)
	}
}

func TestParseNflogShortPayload(t *testing.T) {
	// A truncated payload must not panic; addresses just stay empty.
	d := parseNflog("nftgeo-drop:deny ", []byte{0x45, 0x00}, nil, nil, nil)
	if d.Verdict != "drop" || d.Src != "" {
		t.Errorf("short payload: %+v", d)
	}
}
