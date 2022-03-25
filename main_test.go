package main

import (
	"fmt"
	"github.com/jetstack/cert-manager/pkg/acme/webhook"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/test/acme/dns"
	"io/ioutil"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	restclient "k8s.io/client-go/rest"
	"os"
	"testing"
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

func TestPresent(t *testing.T) {
	configJSONByte, _ := ioutil.ReadFile("testdata/huawei-solver/config.json")
	solver := NewSolver()

	ch := &v1alpha1.ChallengeRequest{
		ResolvedFQDN: "_acme-challenge.asterip.net.",
		ResolvedZone: "asterip.net",
		Config:       &apiextensionsv1.JSON{Raw: configJSONByte},
	}

	err := solver.Present(ch)
	fmt.Println(err)

}

func getSolver() webhook.Solver {
	solver := NewSolver()
	var stopCh <-chan struct{}
	solver.Initialize(&restclient.Config{}, stopCh)
	return solver
}

func getChallengeRequest() *v1alpha1.ChallengeRequest {
	configJSONByte, _ := ioutil.ReadFile("testdata/huawei-solver/config.json")
	ch := &v1alpha1.ChallengeRequest{
		ResolvedFQDN: "_acme-challenge.asterip.net.",
		ResolvedZone: "asterip.net.",
		Config:       &apiextensionsv1.JSON{Raw: configJSONByte},
		Key:          fmt.Sprintf("%q", "test"),
	}
	return ch
}

func Test_huaweiDNSProviderSolver_Present(t *testing.T) {
	solver := getSolver()
	ch := getChallengeRequest()

	err := solver.Present(ch)
	fmt.Println(err)

}

func Test_huaweiDNSProviderSolver_CleanUp(t *testing.T) {
	solver := getSolver()
	ch := getChallengeRequest()
	err := solver.CleanUp(ch)
	fmt.Println(err)
}
