package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type AxwaySTClient struct {
	client   *http.Client
	endpoint string
	auth     string
}

// A wrapper for http.NewRequestWithContext() that prepends axwayst endpoint to URL & sets authorization
// headers and then makes the actual http request.
func (c *AxwaySTClient) GenericAPIRequest(ctx context.Context, method, url string, requestBody any, successCodes []int) (responseBody []byte, statusCode int, errorMessage error) {
	url = c.endpoint + url

	var body io.Reader

	if requestBody != nil {
		jsonData, err := json.Marshal(requestBody)
		if err != nil {
			errorMessage = fmt.Errorf("unable to marshal requestBody into json: %s", err.Error())
			return
		}

		body = strings.NewReader(string(jsonData))
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		errorMessage = fmt.Errorf("error generating http request: %v", err)
		return
	}
	httpReq.Header.Add("Content-Type", "application/json")
	httpReq.Header.Add("Authorization", c.auth)

	httpResp, err := c.client.Do(httpReq)
	if err != nil {
		errorMessage = fmt.Errorf("error doing http request: %v", err)
		return
	}

	var success bool
	for _, successCode := range successCodes {
		if httpResp.StatusCode == successCode {
			success = true
		}
	}

	responseBody, err = io.ReadAll(httpResp.Body)
	statusCode = httpResp.StatusCode

	if err != nil {
		errorMessage = fmt.Errorf("unable to read the http response data body. body: %v", responseBody)
		return
	}
	defer httpResp.Body.Close()

	if !success {
		errorMessage = fmt.Errorf("expected %v http response code for API call, got %d with message %s", successCodes, statusCode, responseBody)
		return
	}

	return
}

func (c *AxwaySTClient) CreateUpdateAPIRequest(ctx context.Context, method, url string, requestBody any, successCodes []int) (statusCode int, errorMessage error) {
	url = c.endpoint + url

	var body io.Reader

	if requestBody != nil {
		jsonData, err := json.Marshal(requestBody)
		if err != nil {
			errorMessage = fmt.Errorf("unable to marshal requestBody into json: %s", err.Error())
			return
		}

		body = strings.NewReader(string(jsonData))
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		errorMessage = fmt.Errorf("error generating http request: %v", err)
		return
	}
	httpReq.Header.Add("Content-Type", "application/json")
	httpReq.Header.Add("Authorization", c.auth)

	httpResp, err := c.client.Do(httpReq)
	if err != nil {
		errorMessage = fmt.Errorf("error doing http request: %v", err)
		return
	}

	var success bool
	for _, successCode := range successCodes {
		if httpResp.StatusCode == successCode {
			success = true
		}
	}

	if !success {
		body, err := io.ReadAll(httpResp.Body)
		defer httpResp.Body.Close()
		if err != nil {
			errorMessage = errors.New("unable to read http request response body to retrieve error message")
			return
		}
		errorMessage = fmt.Errorf("expected %v http response code for API call, got %d with message %s", successCodes, httpResp.StatusCode, body)
		return
	}

	statusCode = httpResp.StatusCode
	return
}
