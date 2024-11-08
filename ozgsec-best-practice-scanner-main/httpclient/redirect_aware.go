package httpclient

import (
	"context"
	"net/http"
	"net/url"
	"sync"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/utils"
)

type redirectAware struct {
	transport *http.Transport
}

func (s *redirectAware) Get(ctx context.Context, url *url.URL) (resp Response, err error) {

	checkRedirect := func(req *http.Request, via []*http.Request) error {
		// disallow the redirect - we are going todo it manually
		return http.ErrUseLastResponse
	}

	// create a new client
	var client http.Client
	if s.transport != nil {
		client = http.Client{
			Transport:     s.transport,
			CheckRedirect: checkRedirect,
		}
	} else {
		// make sure to use the default transport by not providing anything
		client = http.Client{
			CheckRedirect: checkRedirect,
		}
	}

	chain := make([]*http.Response, 0)
	nextUrl := url
	maxRedirects := 10
	for i := 0; i < maxRedirects; i++ {
		req, err := http.NewRequestWithContext(ctx, "GET", nextUrl.String(), nil)
		if err != nil {
			return Response{}, err
		}

		req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36")
		// we want to get the content in English - or at least we are trying to
		req.Header.Add("Accept-Language", "en-GB, en;q=0.9, *;q=0.8")

		res, err := client.Do(req)
		if err != nil {
			return Response{}, err
		}
		// it is a redirect
		chain = append(chain, res)

		// if the response is not a redirect, we are done
		if !utils.Includes([]int{301, 302, 303, 307, 308}, res.StatusCode) {
			return Response{
				resp:          res,
				responseChain: chain,
				mut:           &sync.Mutex{},
			}, nil
		}

		// get the redirect location
		nextUrl, err = res.Location()
		if err != nil {
			// just return what we have
			return Response{
				resp:          res,
				responseChain: chain,
			}, err
		}
	}

	// we have reached the max number of redirects
	return Response{
		resp:          chain[len(chain)-1],
		responseChain: chain,
	}, nil
}

func NewRedirectAwareHttpClient(transport *http.Transport) *redirectAware {
	return &redirectAware{
		transport: transport,
	}
}
