/**
 * a simple program to get all of the IPv6 hosts on a network
 */

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/melbahja/goph"
	"github.com/naoina/toml"
)

type tomlConfig struct {
	KeepLocal      bool
	RetentionTime  int
	RescanInterval int
	OutputFile     string
	IPv6Hosts      map[string]Server
	IPv4Hosts      map[string]Server
}

type Server struct {
	Connection string
	Host       string
	Username   string
	Auth       string
	Keyfile    string
	Password   string
	GophAuth   goph.Auth
	Command    string
}

type Address struct {
	address  net.IP
	hostname string
}

type Host struct {
	mac       net.HardwareAddr
	ipv4hosts []*Address
	ipv6hosts []*Address
}

var hosts map[string]Host

var ipv6HostnameSuffix = "ipv6.ew.wagstrom.net"

const DEFAULT_RETENTION_TIME = 7200
const DEFAULT_RESCAN_INTERVAL = 360

func main() {
	var err error

	hosts = make(map[string]Host)

	configFile := flag.String("config", "", "Filename with configuration")

	flag.Parse()

	var config tomlConfig
	if *configFile != "" {
		f, err := os.Open(*configFile)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		if err := toml.NewDecoder(f).Decode(&config); err != nil {
			panic(err)
		}
	}
	if config.RetentionTime == 0 {
		config.RetentionTime = DEFAULT_RETENTION_TIME
	}
	if config.RescanInterval == 0 {
		config.RescanInterval = DEFAULT_RESCAN_INTERVAL
	}

	agent_auth, err := goph.UseAgent()
	if err != nil {
		log.Fatal(err)
	}

	for key, hostconfig := range config.IPv4Hosts {
		if hostconfig.Auth == "agent" {
			hostconfig.GophAuth = agent_auth
		} else if hostconfig.Auth == "key" {
			keyauth, err := goph.Key(hostconfig.Keyfile, hostconfig.Password)
			if err != nil {
				log.Fatal(err)
			}
			hostconfig.GophAuth = keyauth
		} else if hostconfig.Auth == "password" {
			hostconfig.GophAuth = goph.Password(hostconfig.Password)
		} else {
			log.Fatalf("unable to process authentication for host \"%s\" - method \"%s\"",
				key, hostconfig.Auth)
		}
		config.IPv4Hosts[key] = hostconfig
	}

	for key, hostconfig := range config.IPv6Hosts {
		if hostconfig.Auth == "agent" {
			hostconfig.GophAuth = agent_auth
		} else if hostconfig.Auth == "key" {
			keyauth, err := goph.Key(hostconfig.Keyfile, hostconfig.Password)
			if err != nil {
				log.Fatal(err)
			}
			hostconfig.GophAuth = keyauth
		} else if hostconfig.Auth == "password" {
			hostconfig.GophAuth = goph.Password(hostconfig.Password)
		} else {
			log.Fatalf("unable to process authentication for host \"%s\" - method \"%s\"",
				key, hostconfig.Auth)
		}
		config.IPv6Hosts[key] = hostconfig
	}

	for _, host := range config.IPv4Hosts {
		getIPv4Mappings(host.Host, host.Username, host.Command, host.GophAuth)
	}

	for _, host := range config.IPv6Hosts {
		getIPv6Hosts(host.Host, host.Username, host.Command, config.KeepLocal, host.GophAuth)
	}

	mapHostnames(config.OutputFile)
}

func getIPv4Mappings(host string, user string, cmd string, auth goph.Auth) {
	log.Printf("connecting to %s", host)
	rexp := regexp.MustCompile(`^(?P<hostname>[^ ]+) \((?P<ip>([0-9]{1,3}\.){3}[0-9]{1,3})\) at (?P<mac>([0-9a-f]{1,2}:){5}[0-9a-f]{1,2})`)

	if cmd == "" {
		cmd = "/usr/sbin/arp -a -i eth0"
	}

	client, err := goph.New(user, host, auth)

	if err != nil {
		log.Fatal(err)
	}

	out, err := client.Run(cmd)

	if err != nil {
		log.Fatal(err)
	}

	if err != nil {
		log.Fatal(err)
	}

	lines := strings.Split(string(out), "\n")
	for i := 0; i < len(lines); i++ {
		matches := rexp.FindStringSubmatch(lines[i])
		if len(matches) > 0 {
			hostname := normalizeHostname(strings.ToLower(matches[rexp.SubexpIndex("hostname")]))
			ip := normalizeIPv4Address(matches[rexp.SubexpIndex("ip")])
			mac := normalizeMacAddress(matches[rexp.SubexpIndex("mac")])

			host, exists := hosts[mac.String()]
			if exists {
				log.Printf("host %s already exists", host.mac.String())
			} else {
				host = Host{mac: mac, ipv4hosts: []*Address{}, ipv6hosts: []*Address{}}
				addr := Address{address: ip, hostname: hostname}
				host.ipv4hosts = append(host.ipv4hosts, &addr)
				hosts[mac.String()] = host
			}
		}
	}
}

func getIPv6Hosts(host string, user string, cmd string, keep_local bool, auth goph.Auth) {
	log.Printf("Connecting to %s", host)
	rexp := regexp.MustCompile(`^(?P<ipaddr>[0-9a-f:]+) dev (?P<interface>[0-9a-z\-]+) lladdr (?P<mac>([0-9a-f]{1,2}:){5}[0-9a-f]{1,2})`)

	if cmd == "" {
		cmd = "ip -6 neigh"
	}

	client, err := goph.New(user, host, auth)

	if err != nil {
		log.Fatal(err)
	}

	out, err := client.Run(cmd)

	if err != nil {
		log.Fatal(err)
	}

	lines := strings.Split(string(out), "\n")
	for i := 0; i < len(lines); i++ {
		matches := rexp.FindStringSubmatch(lines[i])
		if len(matches) > 1 {
			mac := normalizeMacAddress(matches[rexp.SubexpIndex("mac")])
			ip := normalizeIPv6Address(matches[rexp.SubexpIndex("ipaddr")])

			host, exists := hosts[mac.String()]
			if exists {
				// log.Printf("**************** found one! %s", mac)
			} else {
				// log.Printf("new mac address: %s", mac)
				host = Host{mac: mac, ipv4hosts: []*Address{}, ipv6hosts: []*Address{}}
				hosts[mac.String()] = host
			}
			if strings.HasPrefix(ip.String(), "fe80") && keep_local == false {
				continue
			}
			addr := Address{address: ip}

			// check if the IP address already exists
			ok := true
			for _, item := range host.ipv6hosts {
				if addr.address.Equal(item.address) {
					ok = false
					break
				}
			}
			// if the address does not exist, then add it
			if ok {
				host.ipv6hosts = append(host.ipv6hosts, &addr)
				// fmt.Printf("length of host.ipv6hosts: %d\n", len(hosts[mac.String()].ipv6hosts))
				// fmt.Printf("length of host.ipv6hosts: %d\n", len(host.ipv6hosts))
				hosts[mac.String()] = host
			}
		} else {
			// log.Printf("failed: %s", lines[i])
		}
	}
	log.Printf("hosts: %d", len(hosts))
}

func mapHostnames(output_file string) {
	output_string := ""

	for key, host := range hosts {
		hostname := getCanonicalHostname(host)
		if hostname != "" {
			// println("key: ", key)
			// println("hostname: ", hostname)
			// println("ipv4hosts: ", len(host.ipv4hosts))
			// println("ipv6hosts: ", len(host.ipv6hosts))
			if len(host.ipv6hosts) > 0 {
				output_string += fmt.Sprintf("# %s\n", key)
			}
			for i := range host.ipv6hosts {
				ipv6host := host.ipv6hosts[i].address
				output_string += fmt.Sprintf("%s %s.%s\n", ipv6host, hostname, ipv6HostnameSuffix)
			}
		}
	}

	fmt.Println(output_string)

	if output_file != "" {
		err := ioutil.WriteFile(output_file, []byte(output_string), 0644)
		if err != nil {
			log.Fatal(err)
		}
	}

}

func getCanonicalHostname(host Host) string {
	for i := range host.ipv4hosts {
		ipv4host := host.ipv4hosts[i]
		if ipv4host.hostname != "" && ipv4host.hostname != "?" {
			return strings.Split(ipv4host.hostname, ".")[0]
		}
	}
	return ""
}

func normalizeHostname(hostname string) string {
	return strings.ToLower(hostname)
}

func normalizeMacAddress(mac string) net.HardwareAddr {
	macParts := strings.Split(mac, ":")
	if len(macParts) != 6 {
		log.Fatalf("got %d parts of mac address %s", len(macParts), mac)
	}
	for i := 0; i < len(macParts); i++ {
		if len(macParts[i]) == 1 {
			macParts[i] = "0" + macParts[i]
		}
	}
	hwAddr, err := net.ParseMAC(strings.Join(macParts, ":"))
	if err != nil {
		log.Fatalf("unable to parse MAC address %s - %s", mac, err)
	}
	return hwAddr
}

func normalizeIPv4Address(addr string) net.IP {
	rv := net.ParseIP(addr)
	if rv == nil {
		log.Fatalf("Unable to parse address %s", addr)
	}
	return rv
}

func normalizeIPv6Address(addr string) net.IP {
	rv := net.ParseIP(addr)
	if rv == nil {
		log.Fatalf("Unable to parse address %s", addr)
	}
	return rv
}
