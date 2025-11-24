package tests

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"sync"
)

type MockServer struct {
	server     *httptest.Server
	mutex      sync.Mutex
	mocks      map[string]map[string][]*MockRequest
	loghttp    bool
	caCertFile string
}

type MockRequest struct {
	method              string
	url                 string
	bodyMatch           map[string]string
	subsetJsonBodyMatch string
	regexBodyMatch      string
	headers             map[string]string
	headersMatchRegex   map[string]string
	statusCode          int
	response            interface{}
	responseString      string
}

func NewMockServer() *MockServer {
	s := &MockServer{
		loghttp: false,
		mocks:   make(map[string]map[string][]*MockRequest),
	}
	s.server = httptest.NewServer(http.HandlerFunc(s.handleRequest))
	httptest.NewTLSServer(http.HandlerFunc(s.handleRequest))
	return s
}

func NewMockTLSServer() *MockServer {
	s := &MockServer{
		loghttp: false,
		mocks:   make(map[string]map[string][]*MockRequest),
	}
	s.server = httptest.NewTLSServer(http.HandlerFunc(s.handleRequest))

	cert := s.server.Certificate()
	tmpFile, err := os.CreateTemp("", "cacert-*.pem")
	if err != nil {
		fmt.Println("Failed to create temp file:", err)
		return nil
	}

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	err = pem.Encode(tmpFile, pemBlock)
	if err != nil {
		fmt.Println("Failed to write CA cert to file:", err)
		return nil
	}

	s.caCertFile = tmpFile.Name()
	return s
}

func (s *MockServer) Certificate() *x509.Certificate {
	return s.server.Certificate()
}

func (s *MockServer) CertificateFile() string {
	return s.caCertFile
}

func (s *MockServer) URL() string {
	return s.server.URL
}

func (s *MockServer) Close() {
	s.server.Close()
	if s.caCertFile != "" {
		os.Remove(s.caCertFile)
	}
}

func (s *MockServer) MockHttpPath(url string) *MockRequest {
	return &MockRequest{url: url, headers: make(map[string]string), headersMatchRegex: make(map[string]string)}
}

func (r *MockRequest) Post() *MockRequest {
	r.method = http.MethodPost
	return r
}

func (r *MockRequest) Get() *MockRequest {
	r.method = http.MethodGet
	return r
}

func (r *MockRequest) MatchExactJsonBody(body map[string]string) *MockRequest {
	r.bodyMatch = body
	return r
}

func (r *MockRequest) MatchJsonBody(jsonString string) *MockRequest {
	r.subsetJsonBodyMatch = jsonString
	return r
}

func (r *MockRequest) MatchBodyRegex(regexPattern string) *MockRequest {
	r.regexBodyMatch = regexPattern
	return r
}

func (r *MockRequest) MatchHeader(header, value string) *MockRequest {
	r.headers[header] = value
	return r
}

func (r *MockRequest) MatchHeaderMatchRegex(header, valueRegexPattern string) *MockRequest {
	r.headersMatchRegex[header] = valueRegexPattern
	return r
}

func (r *MockRequest) Reply(statusCode int) *MockRequest {
	r.statusCode = statusCode
	return r
}

func (r *MockRequest) ResponseJson(response interface{}) *MockRequest {
	r.response = response
	return r
}

func (r *MockRequest) ResponseText(responseString string) *MockRequest {
	r.responseString = responseString
	return r
}

func (s *MockServer) RegisterMock(r *MockRequest) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.mocks[r.url]; !exists {
		s.mocks[r.url] = make(map[string][]*MockRequest)
	}
	s.mocks[r.url][r.method] = append(s.mocks[r.url][r.method], r)
}

func isMapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}

	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func isSubset(fullMap, subsetMap map[string]interface{}) bool {
	for key, subsetValue := range subsetMap {
		fullValue, exists := fullMap[key]
		if !exists {
			return false
		}

		if subsetValueMap, ok := subsetValue.(map[string]interface{}); ok {
			if fullValueMap, ok := fullValue.(map[string]interface{}); ok {
				if !isSubset(fullValueMap, subsetValueMap) {
					return false
				}
			} else {
				return false
			}
		} else if !reflect.DeepEqual(subsetValue, fullValue) {
			return false
		}
	}

	return true
}

func isJsonSubset(fullJSON, subsetJSON string) bool {
	var fullMap, subsetMap map[string]interface{}

	if err := json.Unmarshal([]byte(fullJSON), &fullMap); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(subsetJSON), &subsetMap); err != nil {
		return false
	}

	return isSubset(fullMap, subsetMap)
}

func cloneAndGetRequestBody(req *http.Request) io.ReadCloser {
	reqBodyBuf, _ := io.ReadAll(req.Body)
	copyOfBodyForReading := io.NopCloser(bytes.NewBuffer(reqBodyBuf))
	preservedBody := io.NopCloser(bytes.NewBuffer(reqBodyBuf))
	req.Body = preservedBody
	return copyOfBodyForReading
}

func cloneAndGetRequestBodyAsString(req *http.Request) string {
	bytesValue, _ := io.ReadAll(cloneAndGetRequestBody(req))
	return string(bytesValue)
}

func logHttp(request *http.Request) {
	reqBodyBuf, _ := io.ReadAll(request.Body)
	reqBody := io.NopCloser(bytes.NewBuffer(reqBodyBuf))
	reqBody2 := io.NopCloser(bytes.NewBuffer(reqBodyBuf))
	request.Body = reqBody2
	fmt.Printf("http req URL: %v\n", request.URL.String())
	fmt.Printf("http req method: %v\n", request.Method)
	fmt.Printf("http req body: %v\n", reqBody)
	fmt.Printf("http req headers: %v\n", ToJsonString(request.Header))
}

func ToJsonString(data any) string {
	if jsonString, err := json.Marshal(data); err == nil {
		return string(jsonString)
	}
	return ""
}

func (s *MockServer) handleRequest(w http.ResponseWriter, req *http.Request) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	logHttp(req)

	// check if there is matching mock for the URL and method
	mocks, exists := s.mocks[req.URL.Path][req.Method]
	if !exists {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Iterate over all mocks
mocksLoop:
	for _, mock := range mocks {
		// Check for headers match
		if mock.headers != nil {
			for header, expectedValue := range mock.headers {
				if req.Header.Get(header) != expectedValue {
					continue mocksLoop
				}
			}
		}

		// Check for headers match using regex
		if mock.headersMatchRegex != nil {
			for header, valuePatternRegex := range mock.headersMatchRegex {
				matched, err := regexp.MatchString(valuePatternRegex, req.Header.Get(header))
				if !matched || err != nil {
					continue mocksLoop
				}
			}
		}

		// Check for json body exact match
		if mock.bodyMatch != nil {
			copyOfBody := cloneAndGetRequestBody(req)
			var body map[string]string
			if err := json.NewDecoder(copyOfBody).Decode(&body); err != nil {
				http.Error(w, "Invalid JSON", http.StatusBadRequest)
				return
			}
			if !isMapsEqual(body, mock.bodyMatch) {
				continue mocksLoop
			}
		}

		// check for subset match in json body
		if mock.subsetJsonBodyMatch != "" {
			copyOfBody := cloneAndGetRequestBodyAsString(req)
			if !isJsonSubset(copyOfBody, mock.subsetJsonBodyMatch) {
				continue mocksLoop
			}
		}

		if mock.regexBodyMatch != "" {
			copyOfBody := cloneAndGetRequestBodyAsString(req)
			matched, err := regexp.MatchString(mock.regexBodyMatch, copyOfBody)
			if !matched || err != nil {
				continue mocksLoop
			}
		}

		// serve the response if there are match to a mock
		// For the response body, mock.responseString takes precedence over mock.response
		w.WriteHeader(mock.statusCode)
		if mock.responseString != "" {
			w.Write([]byte(mock.responseString))
		} else if mock.response != nil {
			json.NewEncoder(w).Encode(mock.response)
		}
		return
	}

	// return an http 404 error if no match
	http.Error(w, "Not Found", http.StatusNotFound)
}
