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
	"strconv"
	"time"

	flaggerv1 "github.com/fluxcd/flagger/pkg/apis/flagger/v1beta1"
)

type graphiteDataPoint struct {
	Value     *float64
	TimeStamp time.Time
}

func (gdp *graphiteDataPoint) UnmarshalJSON(data []byte) error {

	var v []interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	switch v[0].(type) {
	case nil:
		// no value
	case string:
		f, err := strconv.ParseFloat(v[0].(string), 64)
		if err != nil {
			return err
		}
		gdp.Value = &f
	default:
		f, ok := v[0].(float64)
		if !ok {
			return fmt.Errorf("error unmarshaling value: %v", v[0])
		}
		gdp.Value = &f
	}

	t, ok := v[1].(int64)
	if !ok {
		return fmt.Errorf("error unmarshaling timestamp: %v", v[1])
	}
	gdp.TimeStamp = time.Unix(t, 0)

	return nil
}

type graphiteTargetResp struct {
	Target     string              `json:"target"`
	DataPoints []graphiteDataPoint `json:"datapoints"`
}

type graphiteResponse []graphiteTargetResp

// GraphiteProvider executes Graphite render URL API queries.
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

// RunQuery executes the Graphite render URL API query and returns the
// the first result as float64.
func (g *GraphiteProvider) RunQuery(query string) (float64, error) {
	query = g.trimQuery(query)
	u, err := url.Parse(fmt.Sprintf("./render?%s", query))
	if err != nil {
		return 0, fmt.Errorf("url.Parase failed: %w", err)
	}

	q := u.Query()
	q.Set("format", "json")
	u.RawQuery = q.Encode()

	u.Path = path.Join(g.url.Path, u.Path)
	u = g.url.ResolveReference(u)

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return 0, fmt.Errorf("http.NewRequest failed: %w", err)
	}

	if g.username != "" && g.password != "" {
		req.SetBasicAuth(g.username, g.password)
	}

	ctx, cancel := context.WithTimeout(req.Context(), g.timeout)
	defer cancel()

	r, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer r.Body.Close()

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return 0, fmt.Errorf("error reading body: %w", err)
	}

	if 400 <= r.StatusCode {
		return 0, fmt.Errorf("error response: %s", string(b))
	}

	var result graphiteResponse
	err = json.Unmarshal(b, &result)
	if err != nil {
		return 0, fmt.Errorf("error unmarshaling result: %w, '%s'", err, string(b))
	}

	var value *float64
	for _, tr := range result {
		for _, dp := range tr.DataPoints {
			if dp.Value != nil {
				value = dp.Value
			}
		}
	}
	if value == nil {
		return 0, ErrNoValuesFound
	}

	return *value, nil
}

// IsOnline runs a simple Graphite render URL API query and returns
// an error if the API is unreachable.
func (g *GraphiteProvider) IsOnline() (bool, error) {
	_, err := g.RunQuery("target=test")
	if err != ErrNoValuesFound {
		return false, fmt.Errorf("running query failed: %w", err)
	}

	return true, nil
}

// trimQuery removes whitespace from the query it's passed.
func (g *GraphiteProvider) trimQuery(query string) string {
	space := regexp.MustCompile(`\s+`)
	return space.ReplaceAllString(query, " ")
}
