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
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"time"

	flaggerv1 "github.com/fluxcd/flagger/pkg/apis/flagger/v1beta1"
)

type graphiteMetric struct {
	Leaf          int         `json:"leaf"`
	Context       interface{} `json:"context"`
	Text          string      `json:"text"`
	Expandable    int         `json:"expandable"`
	ID            string      `json:"id"`
	AllowChildren int         `json:"allowChildren"`
}

type graphiteResponse []graphiteMetric

// GraphiteProvider executes Graphite queries.
type GraphiteProvider struct {
	url      url.URL
	username string
	password string
	timeout  time.Duration
}

// NewGraphiteProvider takes a provider spec and credentials map,
// validates the address, extracts the  credentials map's username
// and password values if provided, and returns a Graphite client
// ready to execute queries against the API.
func NewGraphiteProvider(provider flaggerv1.MetricTemplateProvider, credentials map[string][]byte) (*GraphiteProvider, error) {
	graphiteURL, err := url.Parse(provider.Address)
	if provider.Address == "" || err != nil {
		return nil, fmt.Errorf("%s address %s is not a valid URL", provider.Type, provider.Address)
	}

	graph := GraphiteProvider{
		url:     *graphiteURL,
		timeout: 5 * time.Second,
	}

	if provider.SecretRef == nil {
		return &graph, nil
	}

	if username, ok := credentials["username"]; ok {
		graph.username = string(username)
	} else {
		return nil, fmt.Errorf("%s credentials does not contain a username", provider.Type)
	}

	if password, ok := credentials["password"]; ok {
		graph.password = string(password)
	} else {
		return nil, fmt.Errorf("%s credentials does not contain a password", provider.Type)
	}

	return &graph, nil
}

// RunQuery executes the Graphite query and returns the the response.
// TODO: this will need to conform to the provider interface and return a (float, error).
func (g *GraphiteProvider) RunQuery(query string) (graphiteResponse, error) {
	query = g.trimQuery(query + "&format=json")
	u, err := url.Parse(fmt.Sprintf("./render?%s", query))
	if err != nil {
		return nil, fmt.Errorf("url.Parase failed: %w", err)
	}

	u.Path = path.Join(g.url.Path, u.Path)
	u = g.url.ResolveReference(u)

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("http.NewRequest failed: %w", err)
	}

	if g.username != "" && g.password != "" {
		req.SetBasicAuth(g.username, g.password)
	}

	ctx, cancel := context.WithTimeout(req.Context(), g.timeout)
	defer cancel()

	r, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer r.Body.Close()

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading body: %w", err)
	}

	if 400 <= r.StatusCode {
		return nil, fmt.Errorf("error response: %s", string(b))
	}

	var result graphiteResponse
	err = json.Unmarshal(b, &result)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling result: %w, '%s'", err, string(b))
	}

	return result, nil
}

// IsOnline runs a simple Graphite query and returns an error if the
// API is unreachable.
func (g *GraphiteProvider) IsOnline() (bool, error) {
	_, err := g.RunQuery("target=test")
	if err != nil {
		return false, fmt.Errorf("running query failed: %w", err)
	}

	return true, nil
}

// trimQuery removes whitespace from the query it's passed.
func (g *GraphiteProvider) trimQuery(query string) string {
	space := regexp.MustCompile(`\s+`)
	return space.ReplaceAllString(query, " ")
}
