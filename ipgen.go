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

type ipamArgs struct {
	types.CommonArgs
	IP net.IP `json:"ip,omitempty"`
}

type netconf struct {
	Name string `json:"name"`
	Type string `json:"type"`
	IPAM struct {
		Name    string
		Type    string   `json:"type"`
		Subnet  string   `json:"subnet"`
		Subnets []string `json:"subnets"`
	} `json:"ipam,omitempty"`
	NetName  string `json:"netname"`
	LogLevel string `json:"log_level"`
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
	log.SetOutput(os.Stderr)

	ipamArgs := ipamArgs{}
	if err := types.LoadArgs(args.Args, &ipamArgs); err != nil {
		return err
	}
	log.WithField("ipamArgs", ipamArgs).Debug("Passed args")

	if len(conf.IPAM.Subnets) > 2 {
		return fmt.Errorf("Only a maximum of 2 subnets are supported; 1 for IPv4 and 1 for IPv6")
	}

	conf.IPAM.Subnets = append(conf.IPAM.Subnets, conf.IPAM.Subnet)

	r := &types.Result{}
	for _, subnet := range conf.IPAM.Subnets {
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

		if ipamArgs.IP != nil {
			ip = ipamArgs.IP
			fmt.Fprintf(os.Stderr, "IPGen CNI IPAM request IP: %v\n", ip)
			log.WithField("IP", ip).Info("Assigning provided IP")
		} else {
			name := conf.NetName
			if name == "" {
				name = os.Getenv("CNI_CONTAINERID")
			}

			log.WithFields(log.Fields{
				"name": name,
				"cidr": subnet,
			}).Info("Generating IP address")

			var err error
			ip, err = ipgen.IP(name, subnet)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "IPGen CNI IPAM assigned address: %s\n", ip)
		}
		ipNetwork := net.IPNet{IP: ip, Mask: net.CIDRMask(prefix, bits)}
		if bits == 32 {
			r.IP4 = &types.IPConfig{IP: ipNetwork}
			log.WithField("result.IP4", r.IP4).Info("Result IPv4")
		} else {
			r.IP6 = &types.IPConfig{IP: ipNetwork}
			log.WithField("result.IP6", r.IP6).Info("Result IPv6")
		}
	}

	return r.Print()
}

func cmdDel(args *skel.CmdArgs) error {
	// No cleanup necessary
	return nil
}
