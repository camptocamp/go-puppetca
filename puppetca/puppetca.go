package puppetca

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
}

func NewClient(baseURL, keyFile, certFile, caFile string) (c Client, err error) {
	// Load client cert
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		err = errors.Wrapf(err, "failed to load client cert at %s", certFile)
		return
	}

	// Load CA cert
	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		err = errors.Wrapf(err, "failed to load CA cert at %s", caFile)
		return
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

func (c *Client) GetCertByName(nodename string) (string, error) {
	pem, err := c.Get(fmt.Sprintf("certificate/%s", nodename))
	if err != nil {
		return "", errors.Wrapf(err, "failed to retrieve certificate %s", nodename)
	}
	return pem, nil
}

func (c *Client) DeleteCertByName(nodename string) error {
	_, err := c.Delete(fmt.Sprintf("certificate_status/%s", nodename))
	if err != nil {
		return errors.Wrapf(err, "failed to delete certificate %s", nodename)
	}
	return nil
}

func (c *Client) Get(path string) (string, error) {
	fullPath := fmt.Sprintf("%s/puppet-ca/v1/%s", c.baseURL, path)
	resp, err := c.httpClient.Get(fullPath)
	if err != nil {
		return "", errors.Wrapf(err, "failed to fetch URL %s", fullPath)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch URL %s, got: %s", fullPath, resp.Status)
	}
	defer resp.Body.Close()
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrapf(err, "failed to read body response from %s")
	}

	return string(content), nil
}

func (c *Client) Delete(path string) (string, error) {
	fullPath := fmt.Sprintf("%s/puppet-ca/v1/%s", c.baseURL, path)
	uri, err := url.Parse(fullPath)
	if err != nil {
		return "", errors.Wrapf(err, "failed to parse URL %s", fullPath)
	}
	req := http.Request{
		Method: "DELETE",
		URL:    uri,
	}
	resp, err := c.httpClient.Do(&req)
	if err != nil {
		return "", errors.Wrapf(err, "failed to delete URL %s", fullPath)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to delete URL %s, got: %s", fullPath, resp.Status)
	}
	defer resp.Body.Close()
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrapf(err, "failed to read body response from %s")
	}

	return string(content), nil
}
