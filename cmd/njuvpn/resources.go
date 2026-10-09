package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/libra0037/nju-vpn/internal/ipc"
)

func cmdResources(args []string) error {
	fs := flag.NewFlagSet("resources", flag.ContinueOnError)
	path := fs.String("config", "", "配置文件路径")
	if err := parseNoPositional(fs, args); err != nil {
		return err
	}
	client := ipc.NewClient(*path)
	resp, err := client.Call(ipc.Request{Command: ipc.CmdResources}, 5*time.Second)
	if err != nil {
		return err
	}
	if resp.Code != ipc.CodeOK {
		return errors.New(resp.Message)
	}
	var resources ipc.Resources
	if err := json.Unmarshal([]byte(resp.Message), &resources); err != nil {
		return errors.New("资源快照响应格式非法")
	}
	return printResources(os.Stdout, resources)
}

func printResources(w io.Writer, resources ipc.Resources) error {
	if err := resources.Validate(); err != nil {
		return err
	}
	if len(resources.IP) == 0 {
		if _, err := fmt.Fprintln(w, "IPv4 资源表为空"); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintln(w, "IPv4 资源表"); err != nil {
			return err
		}
		for _, rule := range resources.IP {
			port := resourcePorts(rule.Ports)
			if _, err := fmt.Fprintf(w, "%-8s%-24s%s\n", rule.Protocol, rule.Prefix, port); err != nil {
				return err
			}
		}
	}
	if len(resources.TCPDomains) == 0 {
		if _, err := fmt.Fprintln(w, "\nTCP 域名资源表为空"); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintln(w, "\nTCP 域名资源表"); err != nil {
			return err
		}
		for _, rule := range resources.TCPDomains {
			if _, err := fmt.Fprintf(w, "tcp     %-32s%s\n", rule.Pattern, resourcePorts(rule.Ports)); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintf(w, "\nDNS 服务器\n首选  %s  备选  %s\n", resources.DNS.Primary, resources.DNS.Secondary)
	return err
}

func resourcePorts(ports [2]uint16) string {
	if ports[0] == ports[1] {
		return fmt.Sprint(ports[0])
	}
	return fmt.Sprintf("%d-%d", ports[0], ports[1])
}
