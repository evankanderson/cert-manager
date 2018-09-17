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

package dynudns

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

type fakeDynu struct {
	records    []dynuTxtRecord
	t          *testing.T
	failTokens bool
}

func (f *fakeDynu) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	switch {
	case req.URL.Path == "/v1/oauth2/token":
		if f.failTokens {
			rw.WriteHeader(http.StatusForbidden)
			return
		}
		t := oauth2.Token{
			AccessToken: "abcd",
			TokenType:   "Bearer",
			Expiry:      time.Now().Add(20 * 60 * 1000 * 1000 * 1000),
		}
		b, _ := json.Marshal(t)
		rw.Header().Add("Content-Type", "application/json")
		rw.Write(b)
	case strings.Contains(req.URL.Path, "error"):
		// Simple way to fake an error
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Error requested for " + req.URL.Path))
	case req.URL.Path == "/v1/dns/record/add":
		rr := &dynuTxtRecord{}
		b, _ := ioutil.ReadAll(req.Body)
		json.Unmarshal(b, rr)
		f.t.Logf("Adding %v (and removing from expectations)", rr)
		if rr.Hostname == f.records[0].Hostname && rr.TextData == f.records[0].TextData {
			rw.WriteHeader(http.StatusOK)
		} else {
			rw.WriteHeader(http.StatusInternalServerError)
			rw.Write([]byte(fmt.Sprintf("Want %+v\nGot: %+v", f.records[0], rr)))
		}
		if len(f.records) > 1 {
			f.records = f.records[1:]
		}
	case strings.HasPrefix(req.URL.Path, "/v1/dns/record/delete/"):
		str := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
		id, err := strconv.Atoi(str)
		if err != nil {
			f.t.Errorf("Failed to parse ID(%q): %v", str, err)
		}
		f.t.Logf("Deleting ID %d (%s)", id, str)
		for i, rr := range f.records {
			if rr.ID == int64(id) {
				f.records = append(f.records[:i], f.records[i+1:]...)
				break // Only remove one copy
			}
		}
	case strings.HasPrefix(req.URL.Path, "/v1/dns/records/"):
		// N.B. this does not filter by zone, though the actual Dynu API does.
		b, _ := json.Marshal(f.records)
		rw.Header().Add("Content-Type", "application/json")
		rw.Write(b)
	default:
		f.t.Errorf("Got unexpected URL: %q", req.URL.Path)
		rw.WriteHeader(http.StatusNotFound)
	}
}

func getServer(t *testing.T) (*fakeDynu, *httptest.Server) {
	handler := &fakeDynu{t: t}
	server := httptest.NewServer(handler)
	return handler, server
}

func TestCreateFailure(t *testing.T) {
	fake, server := getServer(t)
	defer server.Close()
	fake.failTokens = true

	_, err := internalNewDNSProvider(server.URL, "ID", "secret", util.RecursiveNameservers)
	if err == nil {
		t.Fatal("Expected error on create, got nothing.")
	}
	if !strings.Contains(err.Error(), "oauth2: cannot fetch token") {
		t.Errorf("Expected oauth2 error message, got %v", err)
	}
	if !strings.Contains(err.Error(), "403 Forbidden") {
		t.Errorf("Expected error message with 403, got %v", err)
	}
}

func TestPresent(t *testing.T) {
	fake, server := getServer(t)
	defer server.Close()
	provider, err := internalNewDNSProvider(server.URL, "ID", "secret", util.RecursiveNameservers)
	if err != nil {
		t.Fatalf("Create provider failed: %v", err)
	}

	rr := dynuTxtRecord{
		DomainName: "example.com",
		NodeName:   "_acme-challenge",
		TextData:   "a-nonce",
	}
	fake.records = append(fake.records, rr)

	err = provider.Present(rr.DomainName, rr.Hostname, rr.TextData)
	if err != nil {
		t.Errorf("Present failed for %v: %v", rr, err)
	}
}

func TestPresentFailure(t *testing.T) {
	fake, server := getServer(t)
	defer server.Close()
	provider, err := internalNewDNSProvider(server.URL, "ID", "secret", util.RecursiveNameservers)

	fake.records = []dynuTxtRecord{
		{Hostname: "error"},
	}
	err = provider.Present("example.com", "_acme-challenge", "a-nonce")
	if err == nil {
		t.Fatalf("Expected error from Present, got none")
	}
	if !strings.Contains(err.Error(), "Want") {
		t.Errorf("Expected 'Want' in string, got: %v", err)
	}
}

func TestCleanUp(t *testing.T) {
	fake, server := getServer(t)
	defer server.Close()
	provider, err := internalNewDNSProvider(server.URL, "ID", "secret", util.RecursiveNameservers)
	if err != nil {
		t.Fatalf("Create provider failed: %v", err)
	}

	fake.records = []dynuTxtRecord{
		{
			DomainName: "example.com",
			NodeName:   "_acme-challenge",
			TextData:   "a-nonce",
			ID:         1234,
			Hostname:   "_acme-challenge.example.com",
		},
		{
			DomainName: "example.com",
			NodeName:   "",
			TextData:   "_spf dummy",
			ID:         1235,
			Hostname:   "example.com",
		},
		{
			DomainName: "example.com",
			NodeName:   "dummy",
			TextData:   "a-string",
			ID:         1236,
			Hostname:   "dummy.example.com",
		},
	}
	rr := &fake.records[0]
	remainder := fake.records[1:]

	err = provider.CleanUp(rr.DomainName, rr.Hostname, rr.TextData)
	if err != nil {
		t.Errorf("Failed to CleanUp record %v: %v", rr, err)
	}
	if len(fake.records) != 2 || reflect.DeepEqual(fake.records, remainder) {
		t.Errorf("Expected only one record remaining: %v\nGot: %v", remainder, fake.records)
	}
	// Expect a second call to CleanUp to pass harmlessly (no-op)
	err = provider.CleanUp(rr.DomainName, rr.Hostname, rr.TextData)
	if err != nil {
		t.Errorf("Failed no-op Cleanup on %v: %v", rr, err)
	}
	if len(fake.records) != 2 || reflect.DeepEqual(fake.records, remainder) {
		t.Errorf("Expected only one record remaining: %v\nGot: %v", remainder, fake.records)
	}
}

func TestErrorHandling(t *testing.T) {
	_, server := getServer(t)
	defer server.Close()
	provider, err := internalNewDNSProvider(server.URL, "ID", "secret", util.RecursiveNameservers)
	if err != nil {
		t.Fatalf("Create provider failed: %v", err)
	}

	err = provider.CleanUp("error.com", "_acme-challenge", "a-nonce")
	if err == nil {
		t.Fatalf("Expected error from CleanUp, got none.")
	}
	if !strings.Contains(err.Error(), "(500)") {
		t.Errorf("Expected 500 error code reported, got %v", err)
	}
	if !strings.Contains(err.Error(), "Error requested for") {
		t.Errorf("Expected 'Error requested for', got %v", err)
	}
}

func TestConnectionClosed(t *testing.T) {
	_, server := getServer(t)
	provider, err := internalNewDNSProvider(server.URL, "ID", "secret", util.RecursiveNameservers)
	if err != nil {
		server.Close()
		t.Fatalf("Create provider failed: %v", err)
	}
	server.Close()
	err = provider.Present("example.com", "_acme-challenge", "a-nonce")
	if err == nil {
		t.Fatalf("Expected connection failure, got success.")
	}
	if !strings.Contains(err.Error(), "dial tcp") {
		t.Errorf("Expected connection closed, got %v", err)
	}
	if !strings.Contains(err.Error(), "No connection could be made") {
		t.Errorf("Expected connection closed, got %v", err)
	}
}
