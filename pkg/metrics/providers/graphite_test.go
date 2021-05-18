/*
Copyright 2020 The Flux authors

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

package providers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	flaggerv1 "github.com/fluxcd/flagger/pkg/apis/flagger/v1beta1"
)

func TestNewGraphiteProvider(t *testing.T) {
	secretRef := &corev1.LocalObjectReference{Name: "graphite"}
	tests := []struct {
		name           string
		addr           string
		secretRef      *corev1.LocalObjectReference
		errExpected    bool
		expectedErrStr string
		credentials    map[string][]byte
	}{{
		name:           "a valid URL, a nil SecretRef, and an empty credentials map are specified",
		addr:           "http://graphite:8080",
		secretRef:      nil,
		errExpected:    false,
		expectedErrStr: "",
		credentials:    map[string][]byte{},
	}, {
		name:           "an invalid URL is specified",
		addr:           ":::",
		secretRef:      nil,
		errExpected:    true,
		expectedErrStr: "graphite address ::: is not a valid URL",
		credentials:    map[string][]byte{},
	}, {
		name:           "a valid URL, a SecretRef, and valid credentials are specified",
		addr:           "http://graphite:8080",
		secretRef:      secretRef,
		errExpected:    false,
		expectedErrStr: "",
		credentials: map[string][]byte{
			"username": []byte("a-username"),
			"password": []byte("a-password"),
		},
	}, {
		name:           "a valid URL, a SecretRef, and credentials without a username are specified",
		addr:           "http://graphite:8080",
		secretRef:      secretRef,
		errExpected:    true,
		expectedErrStr: "graphite credentials does not contain a username",
		credentials: map[string][]byte{
			"password": []byte("a-password"),
		},
	}, {
		name:           "a valid URL, a SecretRef, and credentials without a password are specified",
		addr:           "http://graphite:8080",
		secretRef:      secretRef,
		errExpected:    true,
		expectedErrStr: "graphite credentials does not contain a password",
		credentials: map[string][]byte{
			"username": []byte("a-username"),
		},
	}, {
		name:           "a valid URL, a nil SecretRef, and valid credentials are specified",
		addr:           "http://graphite:8080",
		secretRef:      nil,
		errExpected:    false,
		expectedErrStr: "",
		credentials: map[string][]byte{
			"username": []byte("a-username"),
			"password": []byte("a-password"),
		},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			addr := test.addr
			graph, err := NewGraphiteProvider(flaggerv1.MetricTemplateProvider{
				Address:   addr,
				Type:      "graphite",
				SecretRef: test.secretRef,
			}, test.credentials)

			if test.errExpected {
				require.Error(t, err)
				assert.Equal(t, err.Error(), test.expectedErrStr)
			} else {
				username := ""
				if uname, ok := test.credentials["username"]; ok && test.secretRef != nil {
					username = string(uname)
				}

				password := ""
				if pword, ok := test.credentials["password"]; ok && test.secretRef != nil {
					password = string(pword)
				}

				require.NoError(t, err)
				assert.Equal(t, addr, graph.url.String())
				assert.Equal(t, username, graph.username)
				assert.Equal(t, password, graph.password)
			}
		})
	}
}

func TestGraphiteProvider_IsOnline(t *testing.T) {
	tests := []struct {
		name           string
		expectedResult bool
		errExpected    bool
		code           int
		body           string
	}{{
		"Graphite responds 200 with valid JSON",
		true,
		false,
		200,
		"[]",
	}, {
		"Graphite responds 200 with invalid JSON",
		false,
		true,
		200,
		"[",
	}, {
		"Graphite responds 400",
		false,
		true,
		400,
		"error",
	}, {
		"Graphite responds 500",
		false,
		true,
		500,
		"error",
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/render" || r.URL.Query().Encode() != "format=json&target=test" {
					w.WriteHeader(http.StatusNotFound)
					return
				}

				w.WriteHeader(test.code)
				fmt.Fprintf(w, test.body)
			}))
			defer ts.Close()

			graph, err := NewGraphiteProvider(flaggerv1.MetricTemplateProvider{
				Address: ts.URL,
			}, map[string][]byte{})
			require.NoError(t, err)

			res, err := graph.IsOnline()
			assert.Equal(t, res, test.expectedResult)

			if test.errExpected {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
