package main

import (
	"database/sql"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"

	_ "github.com/lib/pq"
	"github.com/miekg/dns"
)

const IN_FLIGHT = 5

type DnsProvider []string

var DEFAULT_SERVERS = map[string]DnsProvider{
	"honest": {
		"8.8.4.4", "8.8.8.8", // google
		"4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", // level3
		"209.244.0.3", "209.244.0.4", // level3 too
		"84.200.69.80", "84.200.70.40", // dns.watch
		"208.67.222.222", "208.67.220.123", // opendns un-filtered
	},
	"honest-censorship": {
		"208.67.222.123", "208.67.220.123", // opendns filtered
		"8.26.56.26", "8.20.247.20", // comodo securedns
	},
	"bt": {
		"81.139.56.100", "81.139.57.100", // bt (only accessible from their network)
		"127.77.77.99", // unreachable test
	},
}

var wg sync.WaitGroup

func rando(from []chan string) chan string {
	return from[rand.Intn(len(from))]
}

func randString() string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyz0123456789-"

	b := make([]byte, 10+rand.Intn(10))
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func resolve(name string, server string) ([]net.IP, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)

	t, err := dns.Exchange(m, server)
	if nil != err {
		return nil, err
	}
	log.Printf("%s resolved %d records:", server, len(t.Answer))
	var ips []net.IP

	for _, ans := range t.Answer {
		if t, ok := ans.(*dns.A); ok {
			ips = append(ips, t.A)
		}
	}

	return ips, nil
}

func equals(left net.IP, right net.IP) bool {
	if len(left) != len(right) {
		return false
	}

	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}

	return true
}

func contains(haystack []net.IP, needle net.IP) bool {
	for _, item := range haystack {
		if equals(item, needle) {
			return true
		}
	}
	return false
}

func setEquals(left []net.IP, right []net.IP) bool {
	if len(left) != len(right) {
		return false
	}

	for _, item := range right {
		if !contains(left, item) {
			return false
		}
	}

	return true
}

func lookup(from <-chan string, server string, naughtyIps []net.IP) {
	defer wg.Done()

	for name := range from {
		found, err := resolve(name, server)
		if nil != err {
			log.Fatalf("%s couldn't resolve %s: ", server, name, err)
		}

		if len(found) == 0 || setEquals(found, naughtyIps) {
			continue
		}

		log.Printf("result: ", name, found)
	}
}

func nxDomainIps(server string) ([]net.IP, error) {
	var testResps [][]net.IP
	anyFound := false
	for i := 0; i < 5; i += 1 {
		ips, err := resolve(randString(), server)
		if nil != err {
			return nil, err
		}
		testResps = append(testResps, ips)
		anyFound = anyFound || (0 != len(ips))
	}

	if !anyFound {
		return nil, nil
	}

	for _, _ = range testResps {
		// TODO: only return if most? all? hit the same thing
	}

	return testResps[0], nil
}

func lookups() {
	defer wg.Wait()

	db, err := sql.Open("postgres", "")
	if nil != err {
		log.Fatal(err)
	}
	defer db.Close()

	servers := []DnsProvider{
		DEFAULT_SERVERS["honest"],
		DEFAULT_SERVERS["bt"],
	}

	chans := make([][]chan string, len(servers))

	for bid, block := range servers {
		chans[bid] = make([]chan string, len(block))
		for i, server := range block {
			if !strings.ContainsRune(server, ':') {
				server += ":53"
			}

			naughtyIps, err := nxDomainIps(server)
			if nil != err {
				log.Fatalf("uneachable server: %s: ", server, err)
			}

			chans[bid][i] = make(chan string, 3)
			wg.Add(1)
			go lookup(chans[bid][i], server, naughtyIps)
		}
	}

	for _, name := range os.Args[1:] {
		for _, block := range chans {
			rando(block) <- name
		}
	}

	for _, block := range chans {
		for _, server := range block {
			close(server)
		}
	}
}
