package main

import (
	"testing"
)

func TestIPToLong(t *testing.T) {
	val, err := IPToLong("1.2.3.4")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if val != 0x01020304 {
		t.Errorf("expected 0x01020304, got 0x%08x", val)
	}
}

func TestLongToIP(t *testing.T) {
	ip := LongToIP(0x01020304)
	if ip != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %s", ip)
	}
}

func TestParseCIDR(t *testing.T) {
	rng, err := ParseCIDR("1.2.3.0/24")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if rng.Start != 0x01020300 || rng.End != 0x010203FF {
		t.Errorf("expected 0x01020300-0x010203FF, got 0x%08x-0x%08x", rng.Start, rng.End)
	}
}

func TestExpandSlash24(t *testing.T) {
	neighbors := ExpandSlash24("1.2.3.4")
	if len(neighbors) != 253 { // 254 minus the IP itself
		t.Errorf("expected 253 neighbors, got %d", len(neighbors))
	}
	for _, n := range neighbors {
		if n == "1.2.3.4" {
			t.Errorf("neighbors should not contain the original IP")
		}
		if n == "1.2.3.0" || n == "1.2.3.255" {
			t.Errorf("neighbors should not contain .0 or .255")
		}
	}
}
