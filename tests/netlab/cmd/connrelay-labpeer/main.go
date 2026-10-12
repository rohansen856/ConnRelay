// Command connrelay-labpeer runs one side of a ConnRelay connection attempt against
// connrelay-labserver and prints one JSON result line (see package labclient).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/rohansen856/connrelay/core/connrelaycore/connmgr"
	"github.com/rohansen856/connrelay/tests/netlab/labclient"
)

func main() {
	server := flag.String("server", "https://api.lab.invalid", "lab server base URL")
	role := flag.String("role", "phone", "phone or host")
	mode := flag.String("mode", "auto", "auto, webrtc or wss")
	forceRelay := flag.Bool("force-relay", false, "ICE relay-only policy")
	proxy := flag.String("proxy", "", "HTTP CONNECT proxy for HTTPS/WSS (phone)")
	nbytes := flag.Int("bytes", 1<<20, "echo payload size (phone)")
	expect := flag.String("expect", "", "expected path (direct, turn, wss_relay)")
	fallback := flag.Duration("fallback", connmgr.DefaultFallbackDelay, "WSS fallback delay")
	udpBlocked := flag.Bool("udp-blocked", false, "start WSS immediately (cached hint)")
	loops := flag.Int("loops", 1, "host: number of attempts to serve")
	labID := flag.String("lab-id", "default", "pairs one phone run with one host run")
	flag.Parse()

	hc := &http.Client{Timeout: 90 * time.Second, Transport: http.DefaultTransport.(*http.Transport).Clone()}
	if *proxy != "" {
		pu, err := url.Parse(*proxy)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		hc.Transport.(*http.Transport).Proxy = http.ProxyURL(pu)
	}
	for i := 0; i < *loops; i++ {
		r := labclient.Run(labclient.Config{
			Server: *server, LabID: *labID, Role: *role, Mode: *mode, ForceRelay: *forceRelay,
			UDPBlocked: *udpBlocked, Fallback: *fallback, Bytes: *nbytes, HTTPClient: hc, Expect: *expect,
		})
		b, _ := json.Marshal(r)
		fmt.Println(string(b))
		if !r.OK {
			os.Exit(1)
		}
	}
}
