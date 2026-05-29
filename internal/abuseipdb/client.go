package abuseipdb

import (
	"github.com/jm/security-automation-go/internal/abuseipdb/executor"
	"github.com/jm/security-automation-go/internal/abuseipdb/translator"
	"github.com/jm/security-automation-go/internal/abuseipdb/transport"
	"github.com/jm/security-automation-go/internal/httpclient"
)

type Client struct {
	Translator *translator.Translator
	Executor   executor.Executor
}

func NewClient(token string, httpClient httpclient.Client) *Client {
	t := transport.New(httpClient, token)
	return &Client{
		Translator: translator.New(),
		Executor:   executor.New(t),
	}
}
