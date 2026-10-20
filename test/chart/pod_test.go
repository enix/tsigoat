//go:build chart

package chart

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"path"
	"strings"
	"testing"
	"time"
)

// placeholderSecret stands for the files and variables whose content the
// chart does not render: a base64 TSIG secret of 32 bytes.
const placeholderSecret = "cGxhY2Vob2xkZXItc2VjcmV0LW9mLTMyLWJ5dGVzISE=" // gitleaks:allow (placeholder)

// pod emulates what the container of tsigoat sees: the files of its volumes,
// and its environment.
type pod struct {
	release   release
	container *container
	volumes   map[string]volume
	// caBundle stands for the CA bundles that the chart does not render.
	caBundle []byte
}

func newPod(t *testing.T, r release, spec *podSpec, c *container) *pod {
	t.Helper()
	p := &pod{release: r, container: c, volumes: map[string]volume{}, caBundle: caBundle(t)}
	for _, v := range spec.Volumes {
		p.volumes[v.Name] = v
	}
	return p
}

// readFile reads a file of the pod: the files of the ConfigMaps and Secrets
// that the chart renders, and placeholders for the other volumes.
func (p *pod) readFile(name string) ([]byte, error) {
	mount, ok := p.mountOf(name)
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	file := strings.TrimPrefix(name, strings.TrimSuffix(mount.MountPath, "/")+"/")
	v := p.volumes[mount.Name]
	switch {
	case v.ConfigMap != nil && p.release["ConfigMap"][v.ConfigMap.Name] != nil:
		return p.renderedFile(p.release["ConfigMap"][v.ConfigMap.Name], name, file, false)
	case v.Secret != nil && p.release["Secret"][v.Secret.SecretName] != nil:
		return p.renderedFile(p.release["Secret"][v.Secret.SecretName], name, file, true)
	case path.Ext(file) == ".pem" || path.Ext(file) == ".crt":
		return p.caBundle, nil
	default:
		return []byte(placeholderSecret), nil
	}
}

func (*pod) renderedFile(o *object, name, file string, encoded bool) ([]byte, error) {
	data, ok := o.Data[file]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	if !encoded {
		return []byte(data), nil
	}
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("decoding %s of Secret %s: %w", file, o.Metadata.Name, err)
	}
	return decoded, nil
}

// mountOf returns the volume mount that holds a file, the deepest one.
func (p *pod) mountOf(name string) (volumeMount, bool) {
	var found volumeMount
	for _, m := range p.container.VolumeMounts {
		if strings.HasPrefix(name, strings.TrimSuffix(m.MountPath, "/")+"/") && len(m.MountPath) > len(found.MountPath) {
			found = m
		}
	}
	return found, found.MountPath != ""
}

// lookupEnv reads a variable of the container; a placeholder stands for the
// variables that come from elsewhere.
func (p *pod) lookupEnv(name string) (string, bool) {
	for _, v := range p.container.Env {
		if v.Name != name {
			continue
		}
		if v.ValueFrom != nil {
			return placeholderSecret, true
		}
		return v.Value, true
	}
	return "", false
}

// caBundle returns a self-signed CA certificate, in PEM.
func caBundle(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "chart test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
