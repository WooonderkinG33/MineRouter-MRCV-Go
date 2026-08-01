package mrcv

import (
	"crypto/sha256"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"
)

// DefaultBindingSources are the Linux device fingerprints used to compute
// the binding ID. Order matters — it must match the JS implementation.
func DefaultBindingSources() []BindingSource {
	return []BindingSource{
		{Name: "mobo_uuid", Getter: moboUUIDLinux},
		{Name: "disk_serial", Getter: diskSerialLinux},
	}
}

// ComputeBinding produces the 32-byte binding ID: SHA-256 of the
// concatenation of every source value separated by '|'. If no source
// produced data, the platform name is hashed instead (so the vault still
// binds to "this OS", not to an empty string).
func ComputeBinding(sources []BindingSource) []byte {
	if sources == nil {
		sources = DefaultBindingSources()
	}
	h := sha256.New()
	hasData := false
	for _, s := range sources {
		val := ""
		if s.Getter != nil {
			if v, err := s.Getter(); err == nil {
				val = v
			}
		}
		if val != "" {
			hasData = true
		}
		_, _ = h.Write([]byte(val))
		_, _ = h.Write([]byte{'|'})
	}

	// VM guard: on cloned VMs the motherboard UUID and disk serial are
	// identical; the MAC address changes on clone, so it differentiates
	// cloned instances.
	if runtime.GOOS == "linux" && isVM() {
		if mac := firstMAC(); mac != "" {
			_, _ = h.Write([]byte(mac))
			_, _ = h.Write([]byte{'|'})
			hasData = true
		}
	}

	if !hasData {
		_, _ = h.Write([]byte(runtime.GOOS))
	}
	return h.Sum(nil)
}

// moboUUIDLinux reads the motherboard UUID from DMI.
func moboUUIDLinux() (string, error) {
	b, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// systemDisk resolves the device backing the root mount from
// /proc/self/mountinfo. The path cleaning EXACTLY mirrors the JS
// implementation (replace /dev/ -> "", then strip /p\d+$ then \d+$) so the
// binding ID stays byte-identical across languages.
func systemDisk() string {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.Contains(line, " / ") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 6 {
			continue
		}
		path := parts[4]
		if !strings.HasPrefix(path, "/") {
			continue
		}
		name := strings.Replace(path, "/dev/", "", 1)
		name = stripSuffix(name, `p\d+$`)
		name = stripSuffix(name, `\d+$`)
		return name
	}
	return ""
}

// stripSuffix mirrors JS String.replace(pattern, ""): it removes the first
// regexp match in s. For $-anchored patterns this is the final occurrence.
func stripSuffix(s, pattern string) string {
	re := regexp.MustCompile(pattern)
	loc := re.FindStringIndex(s)
	if loc == nil {
		return s
	}
	return s[:loc[0]] + s[loc[1]:]
}

// diskSerialLinux reads the disk serial number from sysfs.
func diskSerialLinux() (string, error) {
	disk := systemDisk()
	if disk == "" {
		return "", os.ErrNotExist
	}
	b, err := os.ReadFile("/sys/block/" + disk + "/device/serial")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

var vmVendors = []string{"qemu", "vmware", "virtualbox", "innotek", "microsoft corporation", "xen"}

// isVM reports whether the machine looks like a virtual machine (Linux DMI).
func isVM() bool {
	b, err := os.ReadFile("/sys/class/dmi/id/sys_vendor")
	if err != nil {
		return false
	}
	vendor := strings.ToLower(strings.TrimSpace(string(b)))
	for _, v := range vmVendors {
		if strings.Contains(vendor, v) {
			return true
		}
	}
	return false
}

// firstMAC returns the first non-internal MAC address (lowercase, no colons).
func firstMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		mac := ifc.HardwareAddr.String()
		if mac == "" || mac == "00:00:00:00:00:00" {
			continue
		}
		return strings.ReplaceAll(mac, ":", "")
	}
	return ""
}
