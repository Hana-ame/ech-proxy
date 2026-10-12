package main

import "testing"

// TestFilenameIs443 pins the exact-suffix rule: only a filename ending in
// ".443.exe" selects port 443. A substring hit in the middle of the name must
// not trigger it — an intermediate build renamed ".443.beta.exe" would
// otherwise bind a privileged port the operator never asked for.
func TestFilenameIs443(t *testing.T) {
	cases := map[string]bool{
		// The intended builds.
		"ech-proxy.443.exe":          true,
		"foo.443.exe":                true,
		"proxy.443.exe":              true,
		"ech-proxy.EXE":              false, // unrelated case, no suffix
		`C:\tools\ech-proxy.443.exe`: true,
		"/opt/ech-proxy.443.exe":     true,

		// Exact suffix, different case on Windows.
		"ech-proxy.443.EXE": true,

		// Substring only — must NOT trigger.
		"ech-proxy.443.beta.exe":  false,
		"ech-proxy.443.debug.exe": false,
		"ech-proxy.443-old.exe":   false,

		// Other suffixes and the historical default.
		"ech-proxy.exe":         false,
		"ech-proxy.8443.exe":    false,
		"ech-proxy.444.exe":     false,
		"443.exe":               false, // the suffix is ".443.exe", not "443.exe"
		"ech-proxy.443":         false, // no .exe
		"ech-proxy.443.zip":     false,
		"ech-proxy.443.exe.txt": false,

		// Empty and odd inputs.
		"":         false,
		"\\":       false,
		".443.exe": true,
	}
	for name, want := range cases {
		if got := filenameIs443(name); got != want {
			t.Errorf("filenameIs443(%q) = %v, want %v", name, got, want)
		}
	}
}
