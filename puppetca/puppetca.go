package puppetca

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

// Client is a Puppet CA client
type Client struct {
	baseURL    string
	httpClient *http.Client
}

func isFile(str string) bool {
	return strings.HasPrefix(str, "/")
}

// NewClient returns a new Client
func NewClient(baseURL, keyStr, certStr, caStr string) (c Client, err error) {
	// Load client cert
	var cert tls.Certificate
	if isFile(certStr) {
		if !isFile(keyStr) {
			err = fmt.Errorf("cert points to a file but key is a string")
			return
		}

		cert, err = tls.LoadX509KeyPair(certStr, keyStr)
		if err != nil {
			err = errors.Wrapf(err, "failed to load client cert from file %s", certStr)
			return c, err
		}
	} else {
		if isFile(keyStr) {
			err = fmt.Errorf("cert is a string but key points to a file")
			return c, err
		}

		cert, err = tls.X509KeyPair([]byte(certStr), []byte(keyStr))
		if err != nil {
			err = errors.Wrapf(err, "failed to load client cert from string")
			return c, err
		}
	}

	// Load CA cert
	var caCert []byte
	if isFile(caStr) {
		caCert, err = ioutil.ReadFile(caStr)
		if err != nil {
			err = errors.Wrapf(err, "failed to load CA cert at %s", caStr)
			return
		}
	} else {
		caCert = []byte(caStr)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tr := &http.Transport{TLSClientConfig: tlsConfig}
	httpClient := &http.Client{Transport: tr}
	c = Client{baseURL, httpClient}

	return
}

// GetCertByName returns the certificate of a node by its name
func (c *Client) GetCertByName(nodename string) (string, error) {
	pem, err := c.Get(fmt.Sprintf("certificate/%s", nodename), nil)
	if err != nil {
		return "", errors.Wrapf(err, "failed to retrieve certificate %s", nodename)
	}
	return pem, nil
}

// DeleteCertByName deletes the certificate of a given node
func (c *Client) DeleteCertByName(nodename string) error {
	_, err := c.Delete(fmt.Sprintf("certificate_status/%s", nodename), nil)
	if err != nil {
		return errors.Wrapf(err, "failed to delete certificate %s", nodename)
	}
	return nil
}

// SubmitRequest submits a CSR
func (c *Client) SubmitRequest(nodename string, pem string) error {
	// Content-Type: text/plain
	headers := map[string]string{
		"Content-Type": "text/plain",
	}
	_, err := c.Put(fmt.Sprintf("certificate_request/%s", nodename), pem, headers)
	if err != nil {
		return errors.Wrapf(err, "failed to submit CSR %s", nodename)
	}
	return nil
}

// SignRequest signs a CSR
func (c *Client) SignRequest(nodename string) error {
	action := "{\"desired_state\":\"signed\"}"
	headers := map[string]string{
		"Content-Type": "text/pson",
	}
	_, err := c.Put(fmt.Sprintf("certificate_status/%s", nodename), action, headers)
	if err != nil {
		return errors.Wrapf(err, "failed to sign CSR %s", nodename)
	}
	return nil
}

// RevokeCert revokes a certificate
func (c *Client) RevokeCert(nodename string) error {
	action := "{\"desired_state\":\"revoked\"}"
	headers := map[string]string{
		"Content-Type": "text/pson",
	}
	_, err := c.Put(fmt.Sprintf("certificate_status/%s", nodename), action, headers)
	if err != nil {
		return errors.Wrapf(err, "failed to revoke certificate %s", nodename)
	}
	return nil
}

// Get performs a GET request
func (c *Client) Get(path string, headers map[string]string) (string, error) {
	req, err := c.newHTTPRequest("GET", path)
	if err != nil {
		return "", err
	}
	return c.Do(req, headers)
}

// Put performs a PUT request
func (c *Client) Put(path, data string, headers map[string]string) (string, error) {
	req, err := c.newHTTPRequest("PUT", path)
	if err != nil {
		return "", err
	}
	req.Body = ioutil.NopCloser(strings.NewReader(data))
	return c.Do(req, headers)
}

// Delete performs a DELETE request
func (c *Client) Delete(path string, headers map[string]string) (string, error) {
	req, err := c.newHTTPRequest("DELETE", path)
	if err != nil {
		return "", err
	}
	return c.Do(req, headers)
}

func (c *Client) newHTTPRequest(method, path string) (*http.Request, error) {
	uri := fmt.Sprintf("%s/puppet-ca/v1/%s", c.baseURL, path)
	req, err := http.NewRequest(method, uri, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create http request for URL %s", uri)
	}
	return req, nil
}

// Do performs an HTTP request
func (c *Client) Do(req *http.Request, headers map[string]string) (string, error) {
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", errors.Wrapf(err, "failed to %s URL %s", req.Method, req.URL)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return "", fmt.Errorf("failed to %s URL %s, got: %s", req.Method, req.URL, resp.Status)
	}
	defer resp.Body.Close()
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrapf(err, "failed to read body response from %s")
	}

	return string(content), nil
}
