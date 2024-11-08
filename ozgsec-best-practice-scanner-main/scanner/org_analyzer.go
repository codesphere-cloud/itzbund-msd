package scanner

import (
	"context"
	"io"
	"net/url"
	"strings"
	"time"
)

const (
	MissingContactField          = "missingContactField"
	InvalidExpiresField          = "invalidExpiresField"
	Expired                      = "expired"
	MissingResponsibleDisclosure = "missingResponsibleDisclosure"
	WrongMimeType                = "wrongMimeType"
	MissingExpiresField          = "missingExpiresField"
)

const (
	InvalidEncryptionField         = "invalidEncryptionField"
	InvalidCanonicalField          = "invalidCanonicalField"
	InvalidPreferredLanguagesField = "invalidPreferredLanguagesField"
	MissingPGPField                = "missingPGPField"
)

func missingContactField(textContent string) bool {
	// check if the string Contact: is included.
	return !strings.Contains(textContent, "Contact:")
}

func missingExpiresField(textContent string) bool {
	return strings.Count(textContent, "Expires:") != 1
}

func invalidExpiresField(textContent string) bool {
	// get the line with the expires statement.
	// check if the date is in the past.
	lines := strings.Split(textContent, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Expires:") {
			// check if the date is in the past.
			expires := strings.Split(line, "Expires:")[1]
			// parse the date
			_, err := time.Parse(time.RFC3339, strings.ToUpper(strings.TrimSpace(expires)))
			if err != nil {
				return true
			}
		}
	}
	return false
}

func invalidEncryptionField(textContent string) bool {
	return strings.Count(textContent, "Encryption:") != 1
}

func invalidCanonicalField(textContent string) bool {
	return strings.Count(textContent, "Canonical:") != 1
}

func invalidPreferredLanguagesField(textContent string) bool {
	return strings.Count(textContent, "Preferred-Languages:") != 1
}

func missingPGPField(textContent string) bool {
	return !strings.Contains(textContent, "--------BEGIN PGP SIGNATURE--------")
}

func isExpired(textContent string) bool {
	// get the line with the expires statement.
	// check if the date is in the past.
	lines := strings.Split(textContent, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Expires:") {
			// check if the date is in the past.
			expires := strings.Split(line, "Expires:")[1]
			// parse the date
			t, err := time.Parse(time.RFC3339, strings.TrimSpace(expires))
			if err != nil {
				return false
			}

			return t.Before(time.Now())
		}
	}
	return false
}

type OrganizationalAnalyzer struct {
	responsibleDisclosureValidator validator[string]
}

func NewOrgAnalyzer() analyzer[any] {
	// init a new validator.
	// it will basically just run all the functions in the map on the same parameter
	validator := NewValidator(
		map[string]func(textContent string) bool{
			MissingContactField: missingContactField,
			InvalidExpiresField: invalidExpiresField,
			Expired:             isExpired,
			MissingExpiresField: missingExpiresField,
		},
		map[string]func(textContent string) bool{
			InvalidEncryptionField:         invalidEncryptionField,
			InvalidCanonicalField:          invalidCanonicalField,
			InvalidPreferredLanguagesField: invalidPreferredLanguagesField,
			MissingPGPField:                missingPGPField,
		},
	)

	return &OrganizationalAnalyzer{
		responsibleDisclosureValidator: validator,
	}
}

func (a OrganizationalAnalyzer) GetAnalysisRuleIds() []AnalysisRuleId {
	return []AnalysisRuleId{
		ResponsibleDisclosure,
	}
}
func (a OrganizationalAnalyzer) Analyze(ctx context.Context, target Target, _ any) (map[AnalysisRuleId]AnalysisResult, error) {
	if !doingAnyChecks(target.Options, a.GetAnalysisRuleIds()) {
		return nil, nil
	}

	start := time.Now()
	// check if we have a cache hit
	// if so return the cached result
	// if not do the analysis and cache the result
	if cached, err := target.Options.CachingLayer.Get(ctx, target.URL.Hostname()); err == nil {
		cachedValue, err := getFromCache(cached, a.GetAnalysisRuleIds())
		if err == nil {
			return cachedValue, nil
		}
	}

	// do a http request to the ./well-known/security.txt
	// copy the url object
	url, err := url.Parse(target.URL.String())
	if err != nil {
		return nil, err
	}
	url.Scheme = "https" // forced by RFC 9116 https://datatracker.ietf.org/doc/html/rfc9116#location
	url.Path = "/.well-known/security.txt"
	res, err := target.Options.HttpClient.Get(ctx, url)
	if err != nil {
		// check if context was canceled
		if ctx.Err() != nil {
			return nil, err
		}

		return map[AnalysisRuleId]AnalysisResult{
			ResponsibleDisclosure: NewAnalysisResult(Failure, map[string]any{
				"error": err.Error(),
			}, []string{MissingResponsibleDisclosure}, nil, time.Since(start)),
		}, nil
	}
	resp := res.Response()
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		r := map[AnalysisRuleId]AnalysisResult{
			ResponsibleDisclosure: NewAnalysisResult(Failure, map[string]any{
				"statusCode": resp.StatusCode,
			}, []string{MissingResponsibleDisclosure}, nil, time.Since(start)),
		}
		// cache the result
		target.Options.CachingLayer.Set(ctx, target.URL.Hostname(), r, 1*time.Hour) // nolint // just swallow the error
		return r, nil
	}
	// check if the mime type does match
	// https://datatracker.ietf.org/doc/html/rfc9116 -> It MUST have a Content-Type of "text/plain" with the default charset parameter set to "utf-8"
	if !(strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/plain") && strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "charset=utf-8")) {
		r := map[AnalysisRuleId]AnalysisResult{
			ResponsibleDisclosure: NewAnalysisResult(Failure, map[string]any{
				"mimeType":   resp.Header.Get("Content-Type"),
				"statusCode": resp.StatusCode,
			}, []string{WrongMimeType}, nil, time.Since(start)),
		}

		// cache the result
		target.Options.CachingLayer.Set(ctx, target.URL.Hostname(), r, 1*time.Hour) // nolint // just swallow the error
		return r, nil
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	textContent := string(b)

	aggregatedResult := map[AnalysisRuleId]AnalysisResult{
		ResponsibleDisclosure: a.responsibleDisclosure(textContent, start),
	}

	// cache the result
	target.Options.CachingLayer.Set(ctx, target.URL.Hostname(), aggregatedResult, 1*time.Hour) // nolint // just swallow the error
	return aggregatedResult, nil
}

/**
 *
 * @requirements
 * REQUIRED: the file "/.well-known/security.txt" is present.
 * REQUIRED: the file "/.well-known/security.txt" contains one or more "Contact:" fields.
 * REQUIRED: the file "/.well-known/security.txt" contains the "Expires:" field ONCE.
 * RECOMMENDED: the file "/.well-known/security.txt" contains the "Encryption:" field, if so only ONCE.
 * RECOMMENDED: the file "/.well-known/security.txt" contains the "Canonical:" field, if so only ONCE.
 * RECOMMENDED: the file "/.well-known/security.txt" contains the "Preferred-Languages:" field, if so only ONCE.
 * RECOMMENDED: the file "/.well-known/security.txt" is signed with a valid PGP signature. https://datatracker.ietf.org/doc/html/draft-foudil-securitytxt-12#section-3.3
 *
 * Example: "Contact: mailto:..."
 * Example: "Contact: tel:.."
 * Example: "Contact: https://..."
 * Example: "Expires: 2021-12-31T18:37:07z"
 *
 */
func (i *OrganizationalAnalyzer) responsibleDisclosure(textContent string, start time.Time) AnalysisResult {
	// validate the content of the security.txt
	didPass, errors, recs := i.responsibleDisclosureValidator.Validate(textContent)
	return NewAnalysisResult(didPass, map[string]any{
		"security.txt": textContent,
	}, errors, recs, time.Since(start))
}
