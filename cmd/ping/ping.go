package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	ping "github.com/summer2186/go-ping"
)

var usage = `
Usage:

    ping [-c count] [-i interval] [-t timeout] [-I interface] [-dns dns] [-debug] [-4] [-6] [--privileged] host

Examples:

    # ping google continuously
    ping www.google.com

    # ping google 5 times
    ping -c 5 www.google.com

    # ping google 5 times at 500ms intervals
    ping -c 5 -i 500ms www.google.com

    # ping google for 10 seconds
    ping -t 10s www.google.com

    # Send a privileged raw ICMP ping
    sudo ping --privileged www.google.com

    # Send ICMP messages with a 100-byte payload
    ping -s 100 1.1.1.1

	# ping with interface
	ping -I eth0 1.1.1.1

	# use specify dns
	ping -dns 8.8.8.8 www.google.com

	# use ipv4
	ping -4 www.google.com

	# use ipv6
	ping -6 www.google.com
`

func main() {
	timeout := flag.Duration("t", time.Second*100000, "")
	interval := flag.Duration("i", time.Second, "")
	count := flag.Int("c", -1, "")
	size := flag.Int("s", 24, "")
	ttl := flag.Int("l", 64, "TTL")
	bindInterface := flag.String("I", "", "")
	privileged := flag.Bool("privileged", false, "")
	dns := flag.String("dns", "", "")
	enableDebug := flag.Bool("debug", false, "")
	ipv4 := flag.Bool("4", false, "")
	ipv6 := flag.Bool("6", false, "")

	flag.Usage = func() {
		fmt.Print(usage)
	}
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		return
	}

	network := "ip"
	if *ipv4 {
		network = "ip4"
	} else if *ipv6 {
		network = "ip6"
	}

	host := flag.Arg(0)
	pinger, err := ping.NewPinger2(host, network, *bindInterface, *dns, *enableDebug)
	if err != nil {
		fmt.Println("ERROR:", err)
		return
	}

	// listen for ctrl-C signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			pinger.Stop()
		}
	}()

	pinger.OnRecv = func(pkt *ping.Packet) {
		fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v ttl=%v\n",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt, pkt.Ttl)
	}
	pinger.OnDuplicateRecv = func(pkt *ping.Packet) {
		fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v ttl=%v (DUP!)\n",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt, pkt.Ttl)
	}
	pinger.OnFinish = func(stats *ping.Statistics) {
		fmt.Printf("\n--- %s ping statistics ---\n", stats.Addr)
		fmt.Printf("%d packets transmitted, %d packets received, %d duplicates, %v%% packet loss\n",
			stats.PacketsSent, stats.PacketsRecv, stats.PacketsRecvDuplicates, stats.PacketLoss)
		fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
			stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
	}

	pinger.Count = *count
	pinger.Size = *size
	pinger.Interval = *interval
	pinger.Timeout = *timeout
	pinger.TTL = *ttl
	//pinger.BindInterface = *bindInterface
	pinger.SetPrivileged(*privileged)
	//pinger.DNS = *dns

	if *bindInterface != "" {
		fmt.Printf("PING %s (%s), interface: %s:\n", pinger.Addr(), pinger.IPAddr(), *bindInterface)
	} else {
		fmt.Printf("PING %s (%s):\n", pinger.Addr(), pinger.IPAddr())
	}
	err = pinger.Run()
	if err != nil {
		fmt.Println("Failed to ping target host:", err)
	}
}
