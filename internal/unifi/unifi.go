/* https://github.com/clbx/kube-port-forward-controller */

package unifi

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"

	"github.com/vegardengen/go-unifi/unifi"
)

type UnifiClient struct {
	Client     *unifi.Client
	SiteID     string
	mutex      sync.Mutex
	controller string
	username   string
	password   string
}

func CreateUnifiClient() (*UnifiClient, error) {
	client := &unifi.Client{}

	unifiURL := os.Getenv("UNIFI_URL")
	if unifiURL == "" {
		return nil, errors.New("could not get UniFi URL from environment variables")
	}

	siteID := os.Getenv("UNIFI_SITE")
	if siteID == "" {
		return nil, errors.New("could not get UniFi site ID from environment variables")
	}

	username := os.Getenv("UNIFI_USER")
	if username == "" {
		return nil, errors.New("could not get UniFi username from environment variables")
	}

	password := os.Getenv("UNIFI_PASSWORD")
	if password == "" {
		return nil, errors.New("could not get UniFi password from environment variables")
	}

	if err := client.SetBaseURL(unifiURL); err != nil {
		return nil, err
	}

	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := &http.Client{
		Jar:       jar,
		Transport: tr,
	}

	if err := client.SetHTTPClient(httpClient); err != nil {
		return nil, fmt.Errorf("failed to set HTTP client: %s", err)
	}

	if err := client.Login(context.Background(), username, password); err != nil {
		return nil, fmt.Errorf("could not log into UniFi controller: %s", err)
	}

	unifiClient := &UnifiClient{
		Client:     client,
		SiteID:     siteID,
		controller: unifiURL,
		username:   username,
		password:   password,
	}

	return unifiClient, nil
}

func (s *Session) WithSession(action func(c *unifi.Client) error) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := action(s.client)
	if err == nil {
		return nil
	}

	if IsSessionExpired(err) {
		if loginErr := s.Client.Login(context.Background(), s.username, s.password); loginErr != nil {
			return fmt.Errorf("re-login to Unifi failed: %w", loginErr)
		}

		return action(s.Client)
	}
}

func isSessionExpired(err error) bool {
	if err == nil {
		return false
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unauthorized") ||
		strings.Contains(msg, "authentication") ||
		strings.Contains(msg, "login required") ||
		strings.Contains(msg, "token")
}
