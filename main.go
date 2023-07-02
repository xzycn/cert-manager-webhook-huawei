package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	"github.com/pkg/errors"
	"github.com/xzycn/cert-manager-webhook-huawei/huawei"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"os"
	"sync"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		klog.Fatal("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName, NewSolver())
}

func NewSolver() webhook.Solver {
	return &huaweiDNSProviderSolver{}
}

type huaweiDNSProviderSolver struct {
	client     *kubernetes.Clientset
	name       string
	dnsClients map[string]*huawei.Client
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
	ch.Key = fmt.Sprintf("%q", ch.Key)
	klog.Infof("start to present TXT record(value: %s): %v %v", ch.ResolvedFQDN, ch.ResolvedZone, ch.Key)
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	klog.Infof("Decoded configuration %v", cfg)

	dnsClient, err := h.getDNSClient(cfg, ch)
	if err != nil {
		klog.Errorf("failed to get dns client: %v", err)
		return err
	}

	err = dnsClient.CreateTXTRecord(ch, cfg.ZoneID)
	if err != nil {
		klog.Errorf("failed to add TXT record: %v", err)
		return err
	}
	klog.Infof("complete presenting TXT record %v %v", ch.ResolvedFQDN, ch.ResolvedZone)

	return nil
}

func (h *huaweiDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	ch.Key = fmt.Sprintf("%q", ch.Key)
	klog.Infof("start to clean TXT record(value: %s): %v %v", ch.ResolvedFQDN, ch.ResolvedZone, ch.Key)
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	klog.Infof("Decoded configuration %v", cfg)

	dnsClient, err := h.getDNSClient(cfg, ch)
	if err != nil {
		klog.Errorf("failed to get dns client: %v", err)
		return err
	}

	record, err := dnsClient.GetTXTRecord(ch)
	if err != nil {
		klog.Errorf("failed to get TXT record: %v", err)
		return err
	}

	err = dnsClient.DeleteTXTRecord(record)
	if err != nil {
		klog.Errorf("failed to delete TXT record: %v", err)
		return err
	}

	klog.Infof("complete cleaning relevant TXT record %v %v", ch.ResolvedFQDN, ch.ResolvedZone)

	return nil
}

func (h *huaweiDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	h.client = cl
	h.dnsClients = make(map[string]*huawei.Client)
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

func (h *huaweiDNSProviderSolver) getDNSClient(cfg *huaweiDNSProviderConfig, ch *v1alpha1.ChallengeRequest) (*huawei.Client, error) {
	zoneID := cfg.ZoneID
	dnsClient, ok := h.dnsClients[zoneID]
	if !ok {
		ak, sk, err := h.getCredential(cfg, ch.ResourceNamespace)
		if err != nil {
			return nil, err
		}
		dnsClient = huawei.NewClient(ak, sk, cfg.Region)
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
