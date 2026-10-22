//go:build !windows

package main

import (
	"fmt"
	"log"
	"sync"
)

type memoryConsoleDriver struct {
	mu      sync.Mutex
	visible bool
}

func newPlatformConsoleDriver() ConsoleWindowDriver {
	return &memoryConsoleDriver{visible: true}
}

func (d *memoryConsoleDriver) IsVisible() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.visible
}

func (d *memoryConsoleDriver) SetVisible(visible bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.visible = visible
}

func (d *memoryConsoleDriver) DisableCloseButton() {}

func startPlatformTray(_ *TrayController) func() {
	return func() {}
}

func copyToClipboardOnPlatform(text string) error {
	return fmt.Errorf("clipboard copy is supported on Windows; text: %s", text)
}

func showNotificationOnPlatform(title, msg string, _ bool) {
	log.Printf("[Notification] %s: %s", title, msg)
}