package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	dns "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/dns/v2"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/dns/v2/model"
	region "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/dns/v2/region"
	"github.com/jetstack/cert-manager/pkg/acme/webhook"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"os"
	"strings"
	"sync"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	//"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
	cmmetav1 "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName,
		NewSolver(),
	)
}

const RecordTypeTXT = "TXT"

func NewSolver() webhook.Solver {
	fmt.Println("debug")
	return &huaweiDNSProviderSolver{}
}

type huaweiDNSProviderSolver struct {
	client     *kubernetes.Clientset
	name       string
	dnsClients map[string]*dns.DnsClient
	sync.RWMutex
}

type huaweiDNSProviderConfig struct {
	Region             string                     `json:"region"`
	ZoneID             string                     `json:"zoneID"`
	AccessKeySecretRef cmmetav1.SecretKeySelector `json:"accessKeySecretRef"`
	SecretKeySecretRef cmmetav1.SecretKeySelector `json:"secretKeySecretRef"`
}

func (h *huaweiDNSProviderSolver) Name() string {
	return "huawei"
}

func (h *huaweiDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	h.Lock()
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	fmt.Printf("Decoded configuration %v", cfg)

	dnsClient, err := h.getDNSClient(cfg, ch)
	if err != nil {
		return err
	}

	_, err = dnsClient.CreateRecordSet(newTXTRecordRequest(ch, cfg.ZoneID))
	if err != nil {
		return errors.Errorf("failed to delete the relevent TXT record: %v", err)
	}

	h.Unlock()
	return nil
}

func (h *huaweiDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	fmt.Printf("Decoded configuration %v", cfg)

	dnsClient, err := h.getDNSClient(cfg, ch)
	if err != nil {
		return err
	}

	record, err := h.getTxtRecord(dnsClient, ch)
	if err != nil {
		return err
	}

	err = h.deleteTxtRecord(dnsClient, record)
	if err != nil {
		return err
	}

	return nil
}

func (h *huaweiDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	h.client = cl
	h.dnsClients = make(map[string]*dns.DnsClient)
	return nil
}

func loadConfig(cfgJSON *extapi.JSON) (*huaweiDNSProviderConfig, error) {
	cfg := &huaweiDNSProviderConfig{}
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (h *huaweiDNSProviderSolver) getDNSClient(cfg *huaweiDNSProviderConfig, ch *v1alpha1.ChallengeRequest) (*dns.DnsClient, error) {
	zoneID := cfg.ZoneID
	dnsClient, ok := h.dnsClients[zoneID]
	if !ok {
		ak, sk, err := h.getCredential(cfg, ch.ResourceNamespace)
		if err != nil {
			return nil, err
		}
		auth := basic.NewCredentialsBuilder().WithAk(ak).WithSk(sk).Build()
		dnsClient := dns.NewDnsClient(
			dns.DnsClientBuilder().
				WithRegion(region.ValueOf(cfg.Region)).
				WithCredential(auth).
				Build())
		h.dnsClients[zoneID] = dnsClient
	}

	return dnsClient, nil

}

func (h *huaweiDNSProviderSolver) getCredential(cfg *huaweiDNSProviderConfig, ns string) (string, string, error) {
	accessKey, err := h.getSecretData(cfg.AccessKeySecretRef, ns)
	if err != nil {
		return "", "", err
	}

	secretKey, err := h.getSecretData(cfg.SecretKeySecretRef, ns)
	if err != nil {
		return "", "", err
	}

	return string(accessKey), string(secretKey), nil
}

func (h *huaweiDNSProviderSolver) getSecretData(selector cmmetav1.SecretKeySelector, ns string) ([]byte, error) {
	secret, err := h.client.CoreV1().Secrets(ns).Get(context.TODO(), selector.Name, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load secret %q", ns+"/"+selector.Name)
	}

	if data, ok := secret.Data[selector.Key]; ok {
		return data, nil
	}

	return nil, errors.Errorf("no key %q in secret %q", selector.Key, ns+"/"+selector.Name)
}

func newTXTRecordRequest(ch *v1alpha1.ChallengeRequest, zoneID string) *model.CreateRecordSetRequest {
	name := extractRecordSetName(ch.ResolvedFQDN, ch.ResolvedZone)

	request := &model.CreateRecordSetRequest{}
	request.ZoneId = zoneID

	request.Body = &model.CreateRecordSetReq{
		Records: []string{
			ch.Key,
		},
		Type: RecordTypeTXT,
		Name: name,
	}
	return request

}
func extractRecordSetName(fqdn, zone string) string {
	name := util.UnFqdn(fqdn)
	if idx := strings.Index(name, "."+zone); idx != -1 {
		return name[:idx]
	}

	return name
}

func (h *huaweiDNSProviderSolver) getTxtRecordsRequest(ch *v1alpha1.ChallengeRequest) *model.ListRecordSetsRequest {
	request := &model.ListRecordSetsRequest{}
	recordType := RecordTypeTXT
	request.Type = &recordType
	nameRequest := extractRecordSetName(ch.ResolvedFQDN, ch.ResolvedZone)
	request.Name = &nameRequest
	recordsRequest := ch.Key
	request.Records = &recordsRequest

	return request
}

func (h *huaweiDNSProviderSolver) getTxtRecord(dnsClient *dns.DnsClient, ch *v1alpha1.ChallengeRequest) (*model.ListRecordSetsWithTags, error) {
	request := h.getTxtRecordsRequest(ch)
	response, err := dnsClient.ListRecordSets(request)
	if err != nil {
		return nil, err
	}

	for _, record := range *response.Recordsets {
		for _, value := range *record.Records {
			if value == ch.Key {
				return &record, nil
			}
		}
	}

	return nil, errors.Errorf("cannot find TXT record for %v", request.Name)

}

func (h *huaweiDNSProviderSolver) deleteTxtRecord(dnsClient *dns.DnsClient, record *model.ListRecordSetsWithTags) error {
	request := &model.DeleteRecordSetRequest{}
	request.ZoneId = *record.ZoneId
	request.RecordsetId = *record.Id
	_, err := dnsClient.DeleteRecordSet(request)
	if err != nil {
		return errors.Errorf("failed to delete TXT record: %v", err)
	}
	return nil
}
