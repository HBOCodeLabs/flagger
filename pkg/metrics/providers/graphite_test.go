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

	flaggerv1 "github.com/fluxcd/flagger/pkg/apis/flagger/v1beta1"
)

func TestNewGraphiteProvider(t *testing.T) {
	addr := "http://graphite:8080"
	graph, err := NewGraphiteProvider(flaggerv1.MetricTemplateProvider{
		Address: addr,
	})

	require.NoError(t, err)
	assert.Equal(t, addr, graph.url.String())
}

func TestNewGraphiteProvider_InvalidURL(t *testing.T) {
	addr := ":::"
	_, err := NewGraphiteProvider(flaggerv1.MetricTemplateProvider{
		Address: addr,
		Type:    "graphite",
	})

	require.Error(t, err)
	assert.Equal(t, err.Error(), fmt.Sprintf("graphite address %s is not a valid URL", addr))
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
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Println(r.URL.Path)
				fmt.Println(r.URL.Query().Encode())
				if r.URL.Path != "/render" || "format=json" != r.URL.Query().Encode() {
					w.WriteHeader(http.StatusNotFound)
					return
				}

				w.WriteHeader(test.code)
				fmt.Fprintf(w, test.body)
			}))
			defer ts.Close()

			graph, err := NewGraphiteProvider(flaggerv1.MetricTemplateProvider{
				Address: ts.URL,
			})
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
