package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"net"
	"net/url"
	"os"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/httpclient"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/resilience"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/utils"
)

type ripeResponse[T any] struct {
	SeeAlso        []any   `json:"see_also"`
	Version        string  `json:"version"`
	DataCallName   string  `json:"data_call_name"`
	DataCallStatus string  `json:"data_call_status"`
	Cached         bool    `json:"cached"`
	Data           T       `json:"data"`
	QueryId        string  `json:"query_id"`
	ProcessTime    float64 `json:"process_time"`
	ServerId       string  `json:"server_id"`
	BuildVersion   string  `json:"build_version"`
	Status         string  `json:"status"`
	StatusCode     int     `json:"status_code"`
	Time           string  `json:"time"`
}

type asn struct {
	Asn    int    `json:"asn"`
	Holder string `json:"holder"`
}

type block struct {
	Resource string `json:"resource"`
	Desc     string `json:"desc"`
	Name     string `json:"name"`
}

type rpkiValidationData struct {
	ValidatingRoas []validatingRoa `json:"validating_roas"`
	Status         string          `json:"status"`
	Validator      string          `json:"validator"`
	Resource       string          `json:"resource"`
	Prefix         string          `json:"prefix"`
}

type validatingRoa struct {
	Origin    string `json:"origin"`
	Prefix    string `json:"prefix"`
	MaxLength int    `json:"max_length"`
	Validity  string `json:"validity"`
}

type prefixOverviewData struct {
	IsLessSpecific   bool     `json:"is_less_specific"`
	Announced        bool     `json:"announced"`
	Asns             []asn    `json:"asns"`
	RelatedPrefixes  []string `json:"related_prefixes"`
	Resource         string   `json:"resource"`
	Type_            string   `json:"type"`
	Block            block    `json:"block"`
	ActualNumRelated int      `json:"actual_num_related"`
	QueryTime        string   `json:"query_time"`
	NumFilteredOut   int      `json:"num_filtered_out"`
}

type circuitBreaker interface {
	Run(func() (any, error)) (any, error)
}

type networkAnalyzer struct {
	client  httpClient
	circuit circuitBreaker
}

type rpkiResult struct {
	IsValid bool   `json:"isValid"`
	Asn     int    `json:"asn"`
	Holder  string `json:"holder"`
	Actual  string `json:"actual"`
	Prefix  string `json:"prefix"`
}

var newRPKIResultFromJSON = cacheSerializerFactory(func(data any) rpkiResult {
	// cast it to a json map
	jsonMap := data.(map[string]any)
	return rpkiResult{
		IsValid: jsonMap["isValid"].(bool),
		Asn:     int(jsonMap["asn"].(float64)),
		Holder:  jsonMap["holder"].(string),
		Actual:  jsonMap["actual"].(string),
		Prefix:  jsonMap["prefix"].(string),
	}
})

func (r rpkiResult) EncodeJSON() ([]byte, error) {
	return json.Marshal(r)
}

var sourceApp = os.Getenv("RIPE_SOURCE_APP")

func (i *networkAnalyzer) ripeCall(ctx context.Context, uri *url.URL) (httpclient.Response, error) {
	query := uri.Query()
	query.Set("sourceapp", sourceApp)
	uri.RawQuery = query.Encode()
	// run this in a circuit breaker
	res, err := i.circuit.Run(func() (any, error) {
		return i.client.Get(ctx, uri)
	})
	if err != nil {
		return httpclient.Response{}, err
	}
	return res.(httpclient.Response), err
}

func (i *networkAnalyzer) getPrefixAndAsn(ctx context.Context, ip net.IP) (string, asn, error) {
	// guess a suffix
	var suffix string
	if ip.To4() != nil {
		// it is an ipv4 address
		suffix = "/32"
	} else {
		// it is an ipv6 address
		suffix = "/128"
	}

	prefix := ip.String() + suffix

	url, _ := url.Parse(`https://stat.ripe.net/data/prefix-overview/data.json`)

	query := url.Query()
	query.Set("resource", prefix)
	url.RawQuery = query.Encode()
	// get the asn
	resp, err := i.ripeCall(ctx, url)
	if err != nil {
		return "", asn{}, err
	}
	var ripeResponse ripeResponse[prefixOverviewData]
	err = resp.DecodeJSON(&ripeResponse)
	if err != nil {
		return "", asn{}, err
	}

	if len(ripeResponse.Data.Asns) == 0 {
		return ripeResponse.Data.Resource, asn{}, nil
	}

	return ripeResponse.Data.Resource, ripeResponse.Data.Asns[0], nil
}

func (i *networkAnalyzer) isRPKIValid(ctx context.Context, target Target, asn asn, prefix string) (rpkiResult, error) {

	if asn.Asn == 0 {
		res := rpkiResult{
			IsValid: false,
			Asn:     0,
			Holder:  "",
			Actual:  "not found",
			Prefix:  prefix,
		}
		// do not cache this error
		return res, nil
	}

	// check if the asn is already cached.
	// if it is, return the cached result
	cached, err := target.Options.CachingLayer.Get(ctx, fmt.Sprintf("%d-%s", asn.Asn, prefix))

	if err == nil {
		return newRPKIResultFromJSON(cached), nil
	}

	var ripeRPKIResponse ripeResponse[rpkiValidationData]
	url, _ := url.Parse(`https://stat.ripe.net/data/rpki-validation/data.json`)
	query := url.Query()
	query.Set("resource", fmt.Sprint(asn.Asn))
	query.Set("prefix", prefix)
	url.RawQuery = query.Encode()
	resp, err := i.ripeCall(ctx, url)
	if err != nil {
		return rpkiResult{}, err
	}
	err = resp.DecodeJSON(&ripeRPKIResponse)
	if err != nil {
		return rpkiResult{}, err
	}

	res := rpkiResult{
		IsValid: ripeRPKIResponse.Data.Status == "valid",
		Asn:     asn.Asn,
		Holder:  asn.Holder,
		Actual:  ripeRPKIResponse.Data.Status,
		Prefix:  prefix,
	}

	// cache the result
	err = target.Options.CachingLayer.Set(ctx, fmt.Sprintf("%d-%s", asn.Asn, res.Prefix), res, 1*time.Hour)
	if err != nil {
		slog.Warn("failed to cache rpki result", "err", err)
		return res, nil
	}
	return res, nil
}

/*
IMMEDIATE ACTION REQUIRED CHECK

	(if a REQUIRED spec is not met, the call to immediate action MUST be shown to the user)

REQUIRED: For each derived prefix the RPKI status MUST be 'valid' (RIPE Stat API) for the check to pass.

	If the status is 'unknown' for one or all of the derived perfixes the call to immediate action MUST NOT be shown to the user.
	If the status is 'invalid_asn' or 'invalid_length' for one or all the call to immediate action MUST be shown to the user.
*/
func (i *networkAnalyzer) rpki(ctx context.Context, target Target) AnalysisResult {
	start := time.Now()

	results := make([]rpkiResult, 0)
	asnRPKI := make(map[int][]rpkiResult)
	for _, ip := range target.IPs {
		// check if we already know that ip is not valid
		cached, err := target.Options.CachingLayer.Get(ctx, ip.String())
		// make sure that the cache is valid
		if err == nil {
			results = append(results, cached.(rpkiResult))
			continue
		}

		prefix, asn, err := i.getPrefixAndAsn(ctx, ip)
		if err != nil {
			return NewAnalysisResult(Unknown, nil, nil, nil, time.Since(start))
		}

		// check if the asn is already cached.
		// if it is, return the cached result
		if resultsForThisASN, ok := asnRPKI[asn.Asn]; ok {
			// we already have the rpki result for this asn
			// but maybe we need to add another result for this ip
			if utils.Every(resultsForThisASN, func(res rpkiResult) bool {
				return res.Prefix != prefix
			}) {
				// we need to add another result for this ip
				// the first element HAS TO EXIST
				res := asnRPKI[asn.Asn][0]
				newResult := rpkiResult{
					IsValid: res.IsValid,
					Asn:     res.Asn,
					Holder:  res.Holder,
					Actual:  res.Actual,
					Prefix:  prefix,
				}
				// save our fake result inside the results array and the cache
				// we can be confident, that this prefix has the same rpki result as the other prefixes inside the same asn.
				results = append(results, newResult)
				asnRPKI[asn.Asn] = append(asnRPKI[asn.Asn], newResult)
			}
			continue
		}

		res, err := i.isRPKIValid(ctx, target, asn, prefix)
		if err != nil {
			return NewAnalysisResult(Unknown, nil, nil, nil, time.Since(start))
		}
		results = append(results, res)
		// cache the result
		asnRPKI[asn.Asn] = []rpkiResult{res}
	}

	isValid := true
	for _, result := range results {
		if !result.IsValid {
			isValid = false
		}
	}

	return NewAnalysisResult(ptr(isValid), results, nil, nil, time.Since(start))
}

func ipv6(_ context.Context, target Target) AnalysisResult {
	start := time.Now()
	// check if the target supports ipv6
	ipv6s := make([]net.IP, 0)
	for _, ip := range target.IPs {
		if ip.To4() == nil {
			ipv6s = append(ipv6s, ip)
		}
	}

	return NewAnalysisResult(ptr(len(ipv6s) > 0), map[string][]net.IP{
		"addresses": ipv6s,
	}, nil, nil, time.Since(start))
}

func (i *networkAnalyzer) Analyze(ctx context.Context, target Target, _ any) (map[AnalysisRuleId]AnalysisResult, error) {
	return map[AnalysisRuleId]AnalysisResult{
		RPKI: maybeDoCheck(RPKI, target.Options, func() AnalysisResult { return i.rpki(ctx, target) }),
		IPv6: maybeDoCheck(IPv6, target.Options, func() AnalysisResult { return ipv6(ctx, target) }),
	}, nil
}

func NewNetworkAnalyzer(client httpClient) analyzer[any] {
	return &networkAnalyzer{
		client:  client,
		circuit: resilience.NewCircuitBreaker(resilience.DefaultClock{}, 10),
	}
}

func (i *networkAnalyzer) GetAnalysisRuleIds() []AnalysisRuleId {
	return []AnalysisRuleId{
		RPKI,
		IPv6,
	}
}
