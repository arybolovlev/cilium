// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"fmt"
	"strings"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model"
)

var supportedTLSVersions = map[string]int{
	"1.2": 2,
	"1.3": 3,
}

var supportedTLSCipherSuites = map[string]struct{}{
	"ECDHE-ECDSA-AES128-GCM-SHA256": {},
	"ECDHE-ECDSA-CHACHA20-POLY1305": {},
	"ECDHE-RSA-AES128-GCM-SHA256":   {},
	"ECDHE-RSA-CHACHA20-POLY1305":   {},
	"ECDHE-ECDSA-AES256-GCM-SHA384": {},
	"ECDHE-RSA-AES256-GCM-SHA384":   {},
}

var supportedTLSECDHCurves = map[string]struct{}{
	"P-256":  {},
	"X25519": {},
}

var supportedTLSSignatureAlgorithms = map[string]struct{}{
	"ecdsa_secp256r1_sha256": {},
	"ecdsa_secp384r1_sha384": {},
	"ecdsa_secp521r1_sha512": {},
	"ecdsa_sha1":             {},
	"ed25519":                {},
	"rsa_pkcs1_sha1":         {},
	"rsa_pkcs1_sha256":       {},
	"rsa_pkcs1_sha384":       {},
	"rsa_pkcs1_sha512":       {},
	"rsa_pss_rsae_sha256":    {},
	"rsa_pss_rsae_sha384":    {},
	"rsa_pss_rsae_sha512":    {},
}

func parseTLSOptions(l gatewayv1.Listener) (*model.TLSOptions, error) {
	if l.TLS == nil {
		return nil, nil
	}

	parsed := &model.TLSOptions{}
	for o, v := range l.TLS.Options {
		option := string(o)
		value := string(v)
		// Validate only 'cilium.io/' options, other should be ignored.
		if !strings.HasPrefix(option, "cilium.io/") {
			continue
		}

		if helpers.IsTLSPassthroughListener(&l) {
			return nil, fmt.Errorf("TLS option %s is not supported on TLS passthrough listeners", option)
		}

		switch option {
		case model.TLSOptionsMinVersion:
			if _, ok := supportedTLSVersions[value]; !ok {
				return nil, fmt.Errorf("TLS Value %s is not supported in %s", value, option)
			}
			parsed.MinVersion = value
		case model.TLSOptionsMaxVersion:
			if _, ok := supportedTLSVersions[value]; !ok {
				return nil, fmt.Errorf("TLS Value %s is not supported in %s", value, option)
			}
			parsed.MaxVersion = value
		case model.TLSOptionsCipherSuites:
			cs := strings.Split(value, ",")
			seen := make(map[string]struct{})
			for i, v := range cs {
				v = strings.TrimSpace(v)
				cs[i] = v
				if _, ok := seen[v]; ok {
					return nil, fmt.Errorf("TLS Value %s duplicates in %s", v, option)
				}
				if _, ok := supportedTLSCipherSuites[v]; !ok {
					return nil, fmt.Errorf("TLS Value %s is not supported in %s", v, option)
				}
				seen[v] = struct{}{}
			}
			parsed.CipherSuites = cs
		case model.TLSOptionsECDHCurves:
			ec := strings.Split(value, ",")
			seen := make(map[string]struct{})
			for i, v := range ec {
				v = strings.TrimSpace(v)
				ec[i] = v
				if _, ok := seen[v]; ok {
					return nil, fmt.Errorf("TLS Value %s duplicates in %s", v, option)
				}
				if _, ok := supportedTLSECDHCurves[v]; !ok {
					return nil, fmt.Errorf("TLS Value %s is not supported in %s", v, option)
				}
				seen[v] = struct{}{}
			}
			parsed.ECDHCurves = ec
		case model.TLSOptionsSignatureAlgorithms:
			sa := strings.Split(value, ",")
			seen := make(map[string]struct{})
			for i, v := range sa {
				v = strings.TrimSpace(v)
				sa[i] = v
				if _, ok := seen[v]; ok {
					return nil, fmt.Errorf("TLS Value %s duplicates in %s", v, option)
				}
				if _, ok := supportedTLSSignatureAlgorithms[v]; !ok {
					return nil, fmt.Errorf("TLS Value %s is not supported in %s", v, option)
				}
				seen[v] = struct{}{}
			}
			parsed.SignatureAlgorithms = sa
		default:
			return nil, fmt.Errorf("TLS Option %s is not supported", option)
		}
	}

	min := model.TLSOptionsDefaultMinVersion
	if parsed.MinVersion != "" {
		min = parsed.MinVersion
	}

	max := model.TLSOptionsDefaultMaxVersion
	if parsed.MaxVersion != "" {
		max = parsed.MaxVersion
	}

	if supportedTLSVersions[min] > supportedTLSVersions[max] {
		return nil, fmt.Errorf("TLS minimum version %s must not exceed maximum version %s", min, max)
	}

	if parsed.MinVersion == "" &&
		parsed.MaxVersion == "" &&
		len(parsed.CipherSuites) == 0 &&
		len(parsed.ECDHCurves) == 0 &&
		len(parsed.SignatureAlgorithms) == 0 {
		return nil, nil
	}

	return parsed, nil
}
