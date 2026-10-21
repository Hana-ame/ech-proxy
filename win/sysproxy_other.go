//go:build !windows

package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

type noopSysProxyDriver struct {
	mu    sync.Mutex
	state SysProxyState
}

func newPlatformSysProxyDriver() SysProxyDriver {
	return &noopSysProxyDriver{
		state: SysProxyState{Mode: SysProxyOff},
	}
}

func (d *noopSysProxyDriver) ApplyPAC(pacURL string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.state = SysProxyState{
		Mode:          SysProxyPAC,
		AutoConfigURL: pacURL,
	}
	return nil
}

func (d *noopSysProxyDriver) ApplyGlobal(proxyHostPort, bypass string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.state = SysProxyState{
		Mode:        SysProxyGlobal,
		ProxyServer: proxyHostPort,
		ProxyBypass: bypass,
	}
	return nil
}

func (d *noopSysProxyDriver) Clear() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.state = SysProxyState{Mode: SysProxyOff}
	return nil
}

func (d *noopSysProxyDriver) Query() (SysProxyState, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.state, nil
}

func installCAOnPlatform(caPath string) error {
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("security", "add-trusted-cert", "-r", "trustRoot", caPath)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("security add-trusted-cert: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	default:
		return fmt.Errorf("auto CA install is supported on Windows (certutil -user); on Linux run: sudo cp %s /usr/local/share/ca-certificates/ech-proxy-ca.crt && sudo update-ca-certificates", caPath)
	}
}