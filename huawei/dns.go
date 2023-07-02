package huawei

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	dns "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/dns/v2"
	hwregion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/dns/v2/region"
	"github.com/pkg/errors"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/dns/v2/model"
	"strings"
)

const RecordTypeTXT = "TXT"

type Client struct {
	dc *dns.DnsClient
}

func NewClient(ak, sk, region string) *Client {
	auth := basic.NewCredentialsBuilder().WithAk(ak).WithSk(sk).Build()
	dnsClient := dns.NewDnsClient(
		dns.DnsClientBuilder().
			WithRegion(hwregion.ValueOf(region)).
			WithCredential(auth).
			Build())

	return &Client{dnsClient}
}

func (c *Client) getTXTRecordsRequest(ch *v1alpha1.ChallengeRequest) *model.ListRecordSetsRequest {
	request := &model.ListRecordSetsRequest{}
	recordType := RecordTypeTXT
	request.Type = &recordType
	nameRequest := extractRecordSetName(ch.ResolvedFQDN, ch.ResolvedZone)
	request.Name = &nameRequest
	recordsRequest := ch.Key
	request.Records = &recordsRequest

	return request
}

func (c *Client) GetTXTRecord(ch *v1alpha1.ChallengeRequest) (*model.ListRecordSetsWithTags, error) {
	request := c.getTXTRecordsRequest(ch)
	response, err := c.dc.ListRecordSets(request)
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

func newTXTRecordRequest(ch *v1alpha1.ChallengeRequest, zoneID string) *model.CreateRecordSetRequest {
	name := extractRecordSetName(ch.ResolvedFQDN, ch.ResolvedZone)

	request := &model.CreateRecordSetRequest{}
	request.ZoneId = zoneID

	request.Body = &model.CreateRecordSetRequestBody{
		Records: []string{
			ch.Key,
		},
		Type: RecordTypeTXT,
		Name: name,
	}
	return request
}

func (c *Client) CreateTXTRecord(ch *v1alpha1.ChallengeRequest, zoneID string) error {
	_, err := c.dc.CreateRecordSet(newTXTRecordRequest(ch, zoneID))
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) DeleteTXTRecord(record *model.ListRecordSetsWithTags) error {
	request := &model.DeleteRecordSetRequest{}
	request.ZoneId = *record.ZoneId
	request.RecordsetId = *record.Id
	_, err := c.dc.DeleteRecordSet(request)
	if err != nil {
		return errors.Errorf("failed to delete TXT record: %v", err)
	}
	return nil
}

func extractRecordSetName(fqdn, zone string) string {
	name := util.UnFqdn(fqdn)
	if idx := strings.Index(name, "."+zone); idx != -1 {
		return name[:idx]
	}

	return name
}
