package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/ipgen/go"
)

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.PluginSupports("0.3.0"))
}

type containerName string

type ipamArgs struct {
	types.CommonArgs
	IP            net.IP
	ContainerName containerName
}

type netConf struct {
	Name string `json:"name"`
	Type string `json:"type"`
	IPAM struct {
		Name    string
		Type    string        `json:"type"`
		Subnet  string        `json:"subnet,omitempty"`
		Gateway net.IP        `json:"gateway,omitempty"`
		Routes  []types.Route `json:"routes,omitempty"`
	} `json:"ipam,omitempty"`
	LogLevel string    `json:"log_level,omitempty"`
	DNS      types.DNS `json:"dns,omitempty"`
}

func cmdAdd(args *skel.CmdArgs) error {
	conf := netConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load config file: %v", err)
	}
	log.WithField("netConf", conf).Debug("Config object")
	// Default log level
	if conf.LogLevel == "" {
		conf.LogLevel = "warn"
	}
	logLevel, err := log.ParseLevel(conf.LogLevel)
	if err != nil {
		return err
	}
	log.SetLevel(logLevel)
	// Print logs to stderr as per the spec
	log.SetOutput(os.Stderr)
	log.WithField("stdin", string(args.StdinData)).Debug("Your configuration")
	ipamArgs := ipamArgs{}
	if err := types.LoadArgs(args.Args, &ipamArgs); err != nil {
		return err
	}
	log.WithField("ipamArgs", ipamArgs).Debug("Processed args")
	_, netwk, err := net.ParseCIDR(conf.IPAM.Subnet)
	if err != nil {
		return err
	}
	subnetPrefix, subnetBits := netwk.Mask.Size()
	r := &types.Result{}
	r.DNS = conf.DNS
	var (
		ip           net.IP
		prefix, bits int
	)
	// If a specific IP address is supplied we will use it and call it a day
	if ipamArgs.IP != nil {
		ip = ipamArgs.IP
		fmt.Fprintf(os.Stderr, "Requested IP address: %v\n", ip)
		log.WithField("IP", ip).Info("Assigning requested IP address")
		if ip.To4() != nil {
			bits = 32
			prefix = bits
		} else {
			bits = 128
			prefix = bits
		}
	} else {
		name := string(ipamArgs.ContainerName)
		if name == "" {
			name = args.ContainerID
		}
		log.WithFields(log.Fields{
			"name": name,
			"cidr": conf.IPAM.Subnet,
		}).Info("Generating IP address")
		ip, err = ipgen.IP(name, conf.IPAM.Subnet)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "IPGen generated IP address: %s\n", ip)
		prefix = subnetPrefix
		bits = subnetBits
	}
	ipNetwork := net.IPNet{IP: ip, Mask: net.CIDRMask(prefix, bits)}
	if bits == 32 {
		r.IP4 = &types.IPConfig{IP: ipNetwork}
		log.WithField("result.IP4", r.IP4).Info("Result IPv4")
		// Only configure gateway and routes if the IP is of the same
		// type as the network
		if subnetBits == bits {
			r.IP4.Gateway = conf.IPAM.Gateway
			r.IP4.Routes = conf.IPAM.Routes
		}
	} else {
		r.IP6 = &types.IPConfig{IP: ipNetwork}
		log.WithField("result.IP6", r.IP6).Info("Result IPv6")
		if subnetBits == bits {
			r.IP6.Gateway = conf.IPAM.Gateway
			r.IP6.Routes = conf.IPAM.Routes
		}
	}
	return r.Print()
}

func cmdDel(args *skel.CmdArgs) error {
	// No cleanup necessary
	return nil
}

func (n *containerName) UnmarshalText(t []byte) error {
	*n = containerName(string(t))
	return nil
}
