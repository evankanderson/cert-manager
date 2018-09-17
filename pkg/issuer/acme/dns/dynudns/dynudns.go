/*
Copyright 2018 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package dynudns implements a DNS provider for solving DNS-01 challenges using
// the Dynu dynamic DNS service. For more information see the Dynu homepage:
//    https://www.dynu.com/en-US/
// And the API guide:
// 	  https://www.dynu.com/Resources/API/Documentation
package dynudns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2/clientcredentials"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers []string
	hostScheme       string
	client           *http.Client
}

type dynuTxtRecord struct {
	// Common data from https://www.dynu.com/Resources/API/Documentation#DNSRecords

	// The name of the managed domain
	DomainName string `json:"domain_name"`
	// The name of the resource in the domain
	NodeName string `json:"node_name"`
	// Must be "TXT"
	RecordType string `json:"record_type"`
	// A DNS TTL (seconds of cache lifetime)
	TTL int `json:"ttl"`
	// Must be true
	State bool `json:"state"`
	// The actual content of the TXT record
	TextData string `json:"text_data"`

	// Only returned in server responses
	ID int64 `json:"id,omitempty"`
	// Only returned in server responses
	DomainID int64 `json:"domain_id,omitempty"`
	// Only returned in server responses
	Hostname string `json:"hostname,omitempty"`
	// Only returned in server responses
	Content string `json:"content,omitempty"`
}

// NewDNSProvider returns a DNSProvider instance configured for Dynu DNS
//
func NewDNSProvider(clientID, clientSecret string, dns01Nameservers []string) (*DNSProvider, error) {
	return internalNewDNSProvider("https://api.dynu.com", clientID, clientSecret, dns01Nameservers)
}

func internalNewDNSProvider(hostScheme, clientID, clientSecret string, dns01Nameservers []string) (*DNSProvider, error) {
	c := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     hostScheme + "/v1/oauth2/token",
	}

	// Verify that tokens can be fetched, if not, return error
	_, err := c.Token(context.Background())
	if err != nil {
		return nil, err
	}

	return &DNSProvider{
		client:           c.Client(context.Background()),
		dns01Nameservers: dns01Nameservers,
		hostScheme:       hostScheme,
	}, nil
}

// Present creates a TXT record to fulfil the dns-01 challenge
func (c *DNSProvider) Present(domain, token, key string) error {
	// fqdn, ttl are unused by ACME DNS
	fqdn, value, ttl, err := util.DNS01Record(domain, key, c.dns01Nameservers)
	if err != nil {
		return err
	}

	authZone, err := util.FindZoneByFqdn(util.ToFqdn(fqdn), util.RecursiveNameservers)
	if err != nil {
		return err
	}

	rr := dynuTxtRecord{
		DomainName: strings.TrimRight(authZone, "."),
		// authZone has a trailing ".", but we use this to trim the "." between NodeName and DomainName
		NodeName:   fqdn[:len(fqdn)-len(authZone)],
		RecordType: "TXT",
		TTL:        ttl,
		State:      true,
		TextData:   value,
	}
	newRecord, err := json.Marshal(rr)
	if err != nil {
		return err
	}

	resp, err := c.apiCall(
		c.hostScheme+"/v1/dns/record/add", func(url string) (*http.Response, error) {
			return c.client.Post(url, "aplication/json", bytes.NewReader(newRecord))
		})
	if err != nil {
		return fmt.Errorf("Add record failed: %v", err)
	}
	resp.Close()

	return nil
}

// CleanUp removes the record matching the specified parameters. It is not
// implemented for the ACME-DNS provider.
func (c *DNSProvider) CleanUp(domain, token, key string) error {
	fqdn, _, _, err := util.DNS01Record(domain, key, c.dns01Nameservers)
	if err != nil {
		return err
	}

	authZone, err := util.FindZoneByFqdn(util.ToFqdn(fqdn), util.RecursiveNameservers)
	if err != nil {
		return err
	}

	records, err := c.getDomain(authZone)
	if err != nil {
		return err
	}
	var record *dynuTxtRecord
	for _, rr := range records {
		if rr.Hostname == strings.TrimRight(fqdn, ".") {
			record = &rr
			break
		}
	}

	if record == nil {
		// Not found, nothing to clean up
		return nil
	}
	log.Printf("Removing record %d for hostname %s", record.ID, record.Hostname)

	_, err = c.apiCall(
		fmt.Sprintf(c.hostScheme+"/v1/dns/record/delete/%d", record.ID), c.client.Get)

	return err
}

// Timeout returns the timeout and interval to use when checking for DNS
// propagation. Adjusting here to cope with spikes in propagation times.
func (c *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 120 * time.Second, 2 * time.Second
}

func (c *DNSProvider) getDomain(zone string) ([]dynuTxtRecord, error) {
	resp, err := c.apiCall(c.hostScheme+"/v1/dns/records/"+zone, c.client.Get)
	if err != nil {
		return nil, err
	}
	defer resp.Close()
	domainList, err := ioutil.ReadAll(resp)
	if err != nil {
		return nil, fmt.Errorf("Unable to read domain response body: %v", err)
	}
	ret := []dynuTxtRecord{}
	err = json.Unmarshal(domainList, &ret)
	return ret, err
}

func (c *DNSProvider) apiCall(url string, method func(string) (*http.Response, error)) (io.ReadCloser, error) {
	resp, err := method(url)
	if err != nil {
		return nil, fmt.Errorf("Unable to fetch %s with %T: %v", url, method, err)
	}
	if resp.StatusCode != 200 {
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			body = []byte(fmt.Sprintf("BODY MISSING: %v", err))
		}
		return nil, fmt.Errorf("HTTP request to %s failed (%d):\n%s", url, resp.StatusCode, body)
	}
	return resp.Body, nil
}
