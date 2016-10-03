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

type netconf struct {
	Name string `json:"name"`
	Type string `json:"type"`
	IPAM struct {
		Name    string
		Type    string   `json:"type"`
		Subnet  string   `json:"subnet"`
		Subnets []string `json:"subnets,omitempty"`
	} `json:"ipam,omitempty"`
	LogLevel string `json:"log_level,omitempty"`
}

func cmdAdd(args *skel.CmdArgs) error {
	conf := netconf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}
	log.WithField("netconf", conf).Debug("Config object")
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

	if len(conf.IPAM.Subnets) > 2 {
		return fmt.Errorf("Only a maximum of 2 subnets are supported; 1 for IPv4 and 1 for IPv6")
	}

	conf.IPAM.Subnets = append(conf.IPAM.Subnets, conf.IPAM.Subnet)

	r := &types.Result{}

	// If a specific IP address is supplied we will use it and call it a day
	if ipamArgs.IP != nil {
		fmt.Fprintf(os.Stderr, "Requested IP address: %v\n", ipamArgs.IP)
		log.WithField("IP", ipamArgs.IP).Info("Assigning requested IP address")
		if ipamArgs.IP.To4() != nil {
			ipNetwork := net.IPNet{IP: ipamArgs.IP, Mask: net.CIDRMask(32, 32)}
			r.IP4 = &types.IPConfig{IP: ipNetwork}
			log.WithField("result.IP4", r.IP4).Info("Result IPv4")
		} else {
			ipNetwork := net.IPNet{IP: ipamArgs.IP, Mask: net.CIDRMask(128, 128)}
			r.IP6 = &types.IPConfig{IP: ipNetwork}
			log.WithField("result.IP6", r.IP6).Info("Result IPv6")
		}
		return r.Print()
	}

	// Otherwise we will process the subnets supplied in the configuration file
	for _, subnet := range conf.IPAM.Subnets {
		if err := processSubnet(subnet, args, ipamArgs, r); err != nil {
			return err
		}
	}

	return r.Print()
}

func processSubnet(subnet string, args *skel.CmdArgs, ipamArgs ipamArgs, r *types.Result) error {
	log.WithField("subnet", subnet).Debug("Processing subnet")
	ip, netwk, err := net.ParseCIDR(subnet)
	if err != nil {
		return err
	}

	prefix, bits := netwk.Mask.Size()

	if bits == 32 && r.IP4 != nil {
		return fmt.Errorf("Only a maximum of 1 IPv4 address is supported.")
	} else if bits == 64 && r.IP6 != nil {
		return fmt.Errorf("Only a maximum of 1 IPv6 address is supported.")
	}

	name := string(ipamArgs.ContainerName)
	if name == "" {
		name = args.ContainerID
	}

	log.WithFields(log.Fields{
		"name": name,
		"cidr": subnet,
	}).Info("Generating IP address")

	ip, err = ipgen.IP(name, subnet)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "IPGen generated IP address: %s\n", ip)
	ipNetwork := net.IPNet{IP: ip, Mask: net.CIDRMask(prefix, bits)}
	if bits == 32 {
		r.IP4 = &types.IPConfig{IP: ipNetwork}
		log.WithField("result.IP4", r.IP4).Info("Result IPv4")
	} else {
		r.IP6 = &types.IPConfig{IP: ipNetwork}
		log.WithField("result.IP6", r.IP6).Info("Result IPv6")
	}
	return nil
}

func cmdDel(args *skel.CmdArgs) error {
	// No cleanup necessary
	return nil
}

func (n *containerName) UnmarshalText(t []byte) error {
	*n = containerName(string(t))
	return nil
}
