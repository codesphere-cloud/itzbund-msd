package httpclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sync"
)

type Response struct {
	resp          *http.Response
	responseChain []*http.Response
	responseBody  []byte
	mut           *sync.Mutex
}

func (r *Response) Response() *http.Response {
	return r.resp
}

func (r *Response) ResponseChain() []*http.Response {
	return r.responseChain
}

func (r *Response) ResponseBody() ([]byte, error) {
	r.mut.Lock()
	defer r.mut.Unlock()
	// check if the response body is already read
	if r.responseBody == nil {
		// read the response body
		io.LimitReader(r.resp.Body, 10*1024*1024) // read only the first 10MB
		body, err := io.ReadAll(r.resp.Body)
		defer r.resp.Body.Close()
		if err != nil {
			return nil, err
		}
		// save the response body
		r.responseBody = body
	}

	return r.responseBody, nil
}

// returns the initial response from the server
// there might be redirects in the request chain
func (r *Response) InitialResponse() *http.Response {
	if len(r.responseChain) == 0 {
		return nil
	}
	return r.responseChain[0]
}

func (r *Response) TLS() *tls.ConnectionState {
	if r.resp == nil {
		return nil
	}
	return r.resp.TLS
}

func (r *Response) DecodeJSON(v interface{}) error {
	res, err := r.ResponseBody()
	if err != nil {
		return err
	}

	return json.Unmarshal(res, v)
}

func (r *Response) GetURL() *url.URL {
	return r.Response().Request.URL
}

type defaultClient struct {
	client *http.Client
}

func (c *defaultClient) Get(ctx context.Context, target *url.URL) (resp Response, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", target.String(), nil)
	if err != nil {
		return Response{}, err
	}

	res, err := c.client.Do(req)
	if err != nil {
		return Response{}, err
	}

	return Response{
		resp:          res,
		responseChain: []*http.Response{res},
		mut:           &sync.Mutex{},
	}, nil
}

func NewDefaultClient() *defaultClient {
	return &defaultClient{
		client: &http.Client{},
	}
}
