// Package config loads and validates the configuration file of tsigoat.
//
// The file is YAML, decoded strictly: unknown fields are errors. Names are
// canonicalised (lower case, trailing dot), secrets may come from the file,
// from another file or from an environment variable, and every error names
// the faulty element with a path such as `zones[0].policy[1].names[0]`.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"go.yaml.in/yaml/v3"
)

// DefaultListen is the listen address when the configuration names none.
const DefaultListen = "[::]:5353"

// Algorithm is a TSIG algorithm.
type Algorithm string

// Supported TSIG algorithms. HMAC-SHA1 and HMAC-MD5 are legacy algorithms:
// they must be named explicitly on a key, and draw a warning.
const (
	HMACSHA256 Algorithm = "hmac-sha256"
	HMACSHA384 Algorithm = "hmac-sha384"
	HMACSHA512 Algorithm = "hmac-sha512"
	HMACSHA224 Algorithm = "hmac-sha224"
	HMACSHA1   Algorithm = "hmac-sha1"
	HMACMD5    Algorithm = "hmac-md5"
)

// Config is a validated configuration.
type Config struct {
	// Listen holds the addresses to listen on, for both UDP and TCP.
	Listen []string
	// AdminListen is the address of the administration HTTP server, which
	// serves the health checks and the metrics; disabled when empty.
	AdminListen string
	Keys        []Key
	Backends    []Backend
	Zones       []Zone
}

// Key is a TSIG key.
type Key struct {
	// Name is the canonical key name.
	Name      string
	Algorithm Algorithm
	Secret    []byte
}

// Backend is a DNS provider that tsigoat applies the updates to.
type Backend struct {
	Name string
	// Type is "powerdns", "rfc2136", "webhook", "cloudflare", "ovh" or
	// "scaleway"; the settings of that type are set.
	Type       string
	PowerDNS   *PowerDNS
	RFC2136    *RFC2136
	Webhook    *Webhook
	Cloudflare *Cloudflare
	OVH        *OVH
	Scaleway   *Scaleway
}

// PowerDNS holds the settings of a PowerDNS backend.
type PowerDNS struct {
	// URL is the base URL of the HTTP API.
	URL      string
	ServerID string
	APIKey   string
	// Timeout bounds every call to the API.
	Timeout time.Duration
	// CAFile is a PEM bundle trusted for the API certificate, on top of the
	// system roots.
	CAFile string
}

// RFC2136 holds the settings of an rfc2136 backend: a name server that
// implements RFC 2136 itself, which tsigoat relays the updates to.
type RFC2136 struct {
	// Server is the host:port of the name server.
	Server string
	// Key signs the messages to the server, and verifies its responses.
	Key Key
	// Timeout bounds every exchange with the server.
	Timeout time.Duration
}

// Webhook holds the settings of a webhook backend: an HTTP endpoint that
// tsigoat posts the updates to, as JSON.
type Webhook struct {
	URL string
	// Timeout bounds every request, from the connection to the response.
	Timeout time.Duration
	// CAFile is a PEM bundle trusted for the certificate of the endpoint, on
	// top of the system roots.
	CAFile string
	// InsecureSkipVerify accepts any certificate.
	InsecureSkipVerify bool
	// FollowRedirects follows the 307 and 308 redirects.
	FollowRedirects bool
	// SignatureSecret signs the requests with HMAC-SHA256, when set.
	SignatureSecret string
	// Username and Password authenticate the requests with HTTP basic
	// authentication, when Username is set.
	Username, Password string
	// BearerToken authenticates the requests with a bearer token, when set.
	BearerToken string
	// Headers come with every request.
	Headers []Header
}

// Cloudflare holds the settings of a cloudflare backend: the API of
// Cloudflare.
type Cloudflare struct {
	// APIToken authenticates the requests.
	APIToken string
	// ZoneIDs holds the identifiers of zones, by canonical name; tsigoat
	// finds the others by name.
	ZoneIDs map[string]string
	// Timeout bounds every call to the API.
	Timeout time.Duration
}

// OVH holds the settings of an ovh backend: the API of OVHcloud.
type OVH struct {
	// Endpoint is the base URL of the API.
	Endpoint string
	// ApplicationKey, ApplicationSecret and ConsumerKey sign the requests,
	// when ApplicationKey is set.
	ApplicationKey, ApplicationSecret, ConsumerKey string
	// ClientID and ClientSecret are the credentials of an OAuth2 service
	// account, which authenticates the requests when ClientID is set.
	ClientID, ClientSecret string
	// Timeout bounds every call to the API.
	Timeout time.Duration
}

// Scaleway holds the settings of a scaleway backend: the Domains and DNS API
// of Scaleway.
type Scaleway struct {
	// SecretKey is the secret key of the API key that authenticates the
	// requests.
	SecretKey string
	// Timeout bounds every call to the API.
	Timeout time.Duration
}

// Header is an HTTP header.
type Header struct {
	Name, Value string
}

// Zone is a zone served by tsigoat.
type Zone struct {
	// Name is the canonical zone name.
	Name string
	// Backend is the name of the backend holding the zone.
	Backend string
	// AllowUnauthenticated accepts unsigned updates of any record.
	AllowUnauthenticated bool
	// Keys lists the canonical names of the keys allowed to update any record
	// of the zone.
	Keys []string
	// Policy grants narrower rights to other keys.
	Policy []Rule
}

// Rule allows a key to update some names and types of a zone. Its
// constraints apply to the records that an update adds.
type Rule struct {
	// Key is the canonical key name.
	Key string
	// Names are canonical name patterns: a "*" label matches exactly one
	// label, a "**" label matches one or more labels.
	Names []string
	// Types are upper-case record types; empty allows every type. "ANY"
	// allows deleting every RRset of a name.
	Types []string
	// MaxTTL bounds the TTL of the records that the rule lets an update add;
	// no bound when zero.
	MaxTTL uint32
	// Content restricts the content of the records that the rule lets an
	// update add.
	Content Content
	// MaxRecords bounds the records that an update may add under the rule;
	// no bound when zero.
	MaxRecords int
}

// Content restricts the content of records.
type Content string

// Contents.
const (
	// AnyContent allows any content.
	AnyContent Content = ""
	// ACMEContent allows the values of ACME DNS-01 challenges alone, in TXT
	// records: one string, the base64url encoding of the SHA-256 digest of a
	// key authorization, as RFC 8555 8.4 defines it.
	ACMEContent Content = "acme"
)

// Options resolve the secrets referenced by the configuration.
type Options struct {
	// LookupEnv reads an environment variable, os.LookupEnv by default.
	LookupEnv func(string) (string, bool)
	// ReadFile reads a file, os.ReadFile by default.
	ReadFile func(string) ([]byte, error)
}

// Load reads, decodes and validates the configuration file at path. Besides
// the configuration, it returns warnings about legal but risky settings.
func Load(path string) (*Config, []string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the operator chooses the configuration file
	if err != nil {
		return nil, nil, fmt.Errorf("reading the configuration: %w", err)
	}
	return Parse(data, Options{})
}

// Parse decodes and validates a configuration.
func Parse(data []byte, options Options) (*Config, []string, error) {
	if options.LookupEnv == nil {
		options.LookupEnv = os.LookupEnv
	}
	if options.ReadFile == nil {
		options.ReadFile = os.ReadFile
	}

	var raw file
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil, errors.New("the configuration is empty")
		}
		return nil, nil, fmt.Errorf("decoding the configuration: %w", err)
	}

	v := &validator{options: options}
	config := v.config(&raw)
	if len(v.errs) > 0 {
		return nil, nil, errors.Join(v.errs...)
	}
	return config, v.warnings, nil
}

// file is the configuration as written.
type file struct {
	Listen   []string      `yaml:"listen"`
	Admin    *fileAdmin    `yaml:"admin"`
	Keys     []fileKey     `yaml:"keys"`
	Backends []fileBackend `yaml:"backends"`
	Zones    []fileZone    `yaml:"zones"`
}

type fileAdmin struct {
	Listen string `yaml:"listen"`
}

type fileKey struct {
	Name       string `yaml:"name"`
	Algorithm  string `yaml:"algorithm"`
	Secret     string `yaml:"secret"`
	SecretFile string `yaml:"secretFile"`
	SecretEnv  string `yaml:"secretEnv"`
}

type fileBackend struct {
	Name       string          `yaml:"name"`
	Type       string          `yaml:"type"`
	PowerDNS   *filePowerDNS   `yaml:"powerdns"`
	RFC2136    *fileRFC2136    `yaml:"rfc2136"`
	Webhook    *fileWebhook    `yaml:"webhook"`
	Cloudflare *fileCloudflare `yaml:"cloudflare"`
	OVH        *fileOVH        `yaml:"ovh"`
	Scaleway   *fileScaleway   `yaml:"scaleway"`
}

type fileOVH struct {
	Endpoint              string      `yaml:"endpoint"`
	ApplicationKey        string      `yaml:"applicationKey"`
	ApplicationSecret     string      `yaml:"applicationSecret"`
	ApplicationSecretFile string      `yaml:"applicationSecretFile"`
	ApplicationSecretEnv  string      `yaml:"applicationSecretEnv"`
	ConsumerKey           string      `yaml:"consumerKey"`
	ConsumerKeyFile       string      `yaml:"consumerKeyFile"`
	ConsumerKeyEnv        string      `yaml:"consumerKeyEnv"`
	OAuth2                *fileOAuth2 `yaml:"oauth2"`
	Timeout               string      `yaml:"timeout"`
}

type fileOAuth2 struct {
	ClientID         string `yaml:"clientId"`
	ClientSecret     string `yaml:"clientSecret"`
	ClientSecretFile string `yaml:"clientSecretFile"`
	ClientSecretEnv  string `yaml:"clientSecretEnv"`
}

type fileScaleway struct {
	SecretKey     string `yaml:"secretKey"`
	SecretKeyFile string `yaml:"secretKeyFile"`
	SecretKeyEnv  string `yaml:"secretKeyEnv"`
	Timeout       string `yaml:"timeout"`
}

type fileCloudflare struct {
	APIToken     string            `yaml:"apiToken"`
	APITokenFile string            `yaml:"apiTokenFile"`
	APITokenEnv  string            `yaml:"apiTokenEnv"`
	ZoneIDs      map[string]string `yaml:"zoneIds"`
	Timeout      string            `yaml:"timeout"`
}

type fileWebhook struct {
	URL                string         `yaml:"url"`
	Timeout            string         `yaml:"timeout"`
	CAFile             string         `yaml:"caFile"`
	InsecureSkipVerify bool           `yaml:"insecureSkipVerify"`
	FollowRedirects    bool           `yaml:"followRedirects"`
	Signature          *fileSignature `yaml:"signature"`
	BasicAuth          *fileBasicAuth `yaml:"basicAuth"`
	Bearer             *fileBearer    `yaml:"bearer"`
	Headers            []fileHeader   `yaml:"headers"`
}

type fileSignature struct {
	Secret     string `yaml:"secret"`
	SecretFile string `yaml:"secretFile"`
	SecretEnv  string `yaml:"secretEnv"`
}

type fileBasicAuth struct {
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
	PasswordFile string `yaml:"passwordFile"`
	PasswordEnv  string `yaml:"passwordEnv"`
}

type fileBearer struct {
	Token     string `yaml:"token"`
	TokenFile string `yaml:"tokenFile"`
	TokenEnv  string `yaml:"tokenEnv"`
}

type fileHeader struct {
	Name      string `yaml:"name"`
	Value     string `yaml:"value"`
	ValueFile string `yaml:"valueFile"`
	ValueEnv  string `yaml:"valueEnv"`
}

type filePowerDNS struct {
	URL        string `yaml:"url"`
	ServerID   string `yaml:"serverId"`
	APIKey     string `yaml:"apiKey"`
	APIKeyFile string `yaml:"apiKeyFile"`
	APIKeyEnv  string `yaml:"apiKeyEnv"`
	Timeout    string `yaml:"timeout"`
	CAFile     string `yaml:"caFile"`
}

type fileRFC2136 struct {
	Server  string   `yaml:"server"`
	Key     *fileKey `yaml:"key"`
	Timeout string   `yaml:"timeout"`
}

type fileZone struct {
	Name                 string     `yaml:"name"`
	Backend              string     `yaml:"backend"`
	AllowUnauthenticated bool       `yaml:"allowUnauthenticated"`
	Keys                 []string   `yaml:"keys"`
	Policy               []fileRule `yaml:"policy"`
}

type fileRule struct {
	Key        string   `yaml:"key"`
	Names      []string `yaml:"names"`
	Types      []string `yaml:"types"`
	ACME       []string `yaml:"acme"`
	MaxTTL     *int64   `yaml:"maxTTL"`
	Content    string   `yaml:"content"`
	MaxRecords *int     `yaml:"maxRecords"`
}
