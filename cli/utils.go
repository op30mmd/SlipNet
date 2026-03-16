package main

import (
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
)

// IPToLong converts an IPv4 address string to uint32.
func IPToLong(ip string) (uint32, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return 0, fmt.Errorf("invalid IP address: %s", ip)
	}
	ipv4 := parsedIP.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf("not an IPv4 address: %s", ip)
	}
	return uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3]), nil
}

// LongToIP converts a uint32 to an IPv4 address string.
func LongToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

// IPRange represents a start and end IP address.
type IPRange struct {
	Start uint32
	End   uint32
}

// ParseCIDR parses a CIDR string (e.g., "1.2.3.0/24") into an IPRange.
func ParseCIDR(cidr string) (IPRange, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return IPRange{}, err
	}
	start, err := IPToLong(ipnet.IP.String())
	if err != nil {
		return IPRange{}, err
	}
	mask := binaryMask(ipnet.Mask)
	end := start | (^mask)
	return IPRange{Start: start, End: end}, nil
}

func binaryMask(mask net.IPMask) uint32 {
	return uint32(mask[0])<<24 | uint32(mask[1])<<16 | uint32(mask[2])<<8 | uint32(mask[3])
}

// GenerateFromRanges picks N random IPs from the provided ranges.
func GenerateFromRanges(ranges []IPRange, count int) []string {
	if len(ranges) == 0 {
		return nil
	}

	cumulativeSizes := make([]uint64, len(ranges))
	var cumulative uint64
	for i, r := range ranges {
		cumulative += uint64(r.End - r.Start + 1)
		cumulativeSizes[i] = cumulative
	}
	totalIps := cumulative

	seen := make(map[string]bool)
	var result []string
	maxAttempts := count * 3
	attempts := 0

	for len(result) < count && attempts < maxAttempts {
		attempts++
		pos := rand.Uint64() % totalIps

		// Binary search to find which range pos falls into
		lo, hi := 0, len(ranges)-1
		for lo < hi {
			mid := (lo + hi) / 2
			if cumulativeSizes[mid] <= pos {
				lo = mid + 1
			} else {
				hi = mid
			}
		}

		start := ranges[lo].Start
		var offset uint64
		if lo > 0 {
			offset = pos - cumulativeSizes[lo-1]
		} else {
			offset = pos
		}
		ip := LongToIP(start + uint32(offset))
		if !seen[ip] {
			seen[ip] = true
			result = append(result, ip)
		}
	}

	return result
}

// ExpandSlash24 returns all 254 IPs in the /24 subnet of the given IP (excluding .0 and .255).
func ExpandSlash24(ip string) []string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return nil
	}
	prefix := strings.Join(parts[:3], ".")
	var result []string
	for i := 1; i <= 254; i++ {
		neighbor := fmt.Sprintf("%s.%d", prefix, i)
		if neighbor != ip {
			result = append(result, neighbor)
		}
	}
	return result
}

// ParseIpRangeString parses a string like "1.2.3.4-1.2.3.10" or "1.2.3.4" or CIDR.
func ParseIpRangeString(s string) ([]IPRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}

	// Try CIDR
	if strings.Contains(s, "/") {
		r, err := ParseCIDR(s)
		if err == nil {
			return []IPRange{r}, nil
		}
	}

	// Try range "start-end"
	if strings.Contains(s, "-") {
		parts := strings.Split(s, "-")
		if len(parts) == 2 {
			start, err1 := IPToLong(strings.TrimSpace(parts[0]))
			end, err2 := IPToLong(strings.TrimSpace(parts[1]))
			if err1 == nil && err2 == nil && start <= end {
				return []IPRange{{Start: start, End: end}}, nil
			}
		}
	}

	// Try single IP
	ip, err := IPToLong(s)
	if err == nil {
		return []IPRange{{Start: ip, End: ip}}, nil
	}

	return nil, fmt.Errorf("invalid IP range format: %s", s)
}
