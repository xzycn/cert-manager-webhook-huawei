package main

import (
	"os"
	"testing"

	"github.com/jetstack/cert-manager/test/acme/dns"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

func TestRunsSuite(t *testing.T) {
	fixture := dns.NewFixture(NewSolver(),
		dns.SetResolvedZone(zone),
		dns.SetManifestPath("testdata/huawei-solver"),
		dns.SetAllowAmbientCredentials(false),
	)
	fixture.RunConformance(t)
}
