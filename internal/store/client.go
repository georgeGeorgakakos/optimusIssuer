// Package store talks to an OptimusDB agent over its existing command API.
//
// optimusIssuer keeps no database of its own. Requests, issued credential
// records, trusted issuers and revocations all live in OptimusDB stores, which
// means they replicate across the swarm and are captured by the existing
// export. This service is stateless and can be restarted or rescheduled
// without losing anything.
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	StoreTrust     = "kbtrust"
	StoreWhoIsWho  = "whoiswho"
	StoreIssuance  = "kbissuance"
)

// Client is a thin wrapper over the agent command endpoint.
type Client struct {
	BaseURL string
	Context string
	HTTP    *http.Client

	// Credential and Key allow this service to authenticate to the agents once
	// they enforce credentials. Until then both may be empty.
	Presenter Presenter
}

// Presenter builds an Authorization header value. It is an interface so that
// the service compiles and runs before the agents enforce authentication.
type Presenter interface {
	Authorization(ctx context.Context, baseURL string) (string, error)
}

// New returns a client for one agent.
func New(baseURL, apiContext string) *Client {
	if apiContext == "" {
		apiContext = "swarmkb"
	}
	return &Client{
		BaseURL: baseURL,
		Context: apiContext,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

type command struct {
	Method   map[string]string        `json:"method"`
	DSType   string                   `json:"dstype"`
	Criteria []map[string]interface{} `json:"criteria"`
}

func (c *Client) do(ctx context.Context, cmd command, out interface{}) error {
	body, err := json.Marshal(cmd)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/%s/command", c.BaseURL, c.Context), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Presenter != nil {
		auth, err := c.Presenter.Authorization(ctx, c.BaseURL)
		if err != nil {
			return fmt.Errorf("store: build authorization: %w", err)
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("store: %s unreachable: %w", c.BaseURL, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("store: agent returned %d: %s", resp.StatusCode, truncate(raw, 300))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		// The command API returns a bare string on a successful write, which is
		// not an error for callers that passed a nil out.
		return fmt.Errorf("store: decode response: %w (body %s)", err, truncate(raw, 200))
	}
	return nil
}

// Put writes one document.
func (c *Client) Put(ctx context.Context, dstype string, doc map[string]interface{}) error {
	return c.do(ctx, command{
		Method:   map[string]string{"cmd": "crudput"},
		DSType:   dstype,
		Criteria: []map[string]interface{}{doc},
	}, nil)
}

// Get returns documents matching criteria. An empty criteria map returns all.
func (c *Client) Get(ctx context.Context, dstype string,
	criteria map[string]interface{}) ([]map[string]interface{}, error) {

	var out []map[string]interface{}
	if criteria == nil {
		criteria = map[string]interface{}{}
	}
	err := c.do(ctx, command{
		Method:   map[string]string{"cmd": "crudget"},
		DSType:   dstype,
		Criteria: []map[string]interface{}{criteria},
	}, &out)
	return out, err
}

// PutTyped marshals v through JSON before writing, so callers may pass structs.
func (c *Client) PutTyped(ctx context.Context, dstype string, v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(b, &doc); err != nil {
		return err
	}
	return c.Put(ctx, dstype, doc)
}

// Health reports whether the agent answers.
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/%s/agent/status", c.BaseURL, c.Context), nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("store: agent status returned %d", resp.StatusCode)
	}
	return nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
