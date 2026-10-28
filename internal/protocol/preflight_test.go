package protocol

import (
	"strings"
	"testing"
	"time"
)

func TestPreflightHelloValidation(t *testing.T) {
	now := time.Now()
	valid := Hello{Version: 2, Type: "preflight", TimestampMS: now.UnixMilli(), PreflightKey: strings.Repeat("a", 64)}
	if err := validateHello(valid, now); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Hello){
		func(h *Hello) { h.PreflightKey = "" },
		func(h *Hello) { h.PreflightKey = strings.Repeat("A", 64) },
		func(h *Hello) { h.ID = strings.Repeat("b", 64) },
		func(h *Hello) { h.Services = []string{"ssh"} },
		func(h *Hello) { h.Type = "control"; h.Services = []string{"ssh"} },
		func(h *Hello) { h.Type = "data"; h.ID = strings.Repeat("b", 64) },
	} {
		h := valid
		mutate(&h)
		if err := validateHello(h, now); err == nil {
			t.Errorf("accepted invalid hello: %+v", h)
		}
	}
}
