package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"io"
	"sync"

	"log"
	"net/http"
	"net/url"
)

const authorizationHeader = "Proxy-Authorization"

const proxyStringFormat = "<HOST>:<PORT>:<USER>:<PASS>"

const expectedProxyStringSplitCount = 4

type Proxy interface {
	Request(request http.Request, proxyURL url.URL, proxyUser string, proxyPassword string) (*http.Response, error)

	RequestWithRandomProxy(request http.Request) (proxyURL *url.URL, response *http.Response, err error)
}

type Cache struct {
	folder      string
	hash        hash.Hash
	knownValues map[string][]byte
	mutex       *sync.Mutex
}

func calcHash(data string) string {
	sha := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sha[:])
}

func (c *Cache) has(key string) bool {
	hashValue := calcHash(key)

	c.mutex.Lock()
	_, ok := c.knownValues[hashValue]
	c.mutex.Unlock()

	return ok
}

// func (c *Cache) get(key string) ([]byte, error) {
// 	hashValue := calcHash(key)

// 	// Try to get content. Error if not found.
// 	c.mutex.Lock()
// 	content, ok := c.knownValues[hashValue]
// 	c.mutex.Unlock()
// 	if !ok {
// 		sigolo.Debug("Cache doen't know key '%s'", hashValue)
// 		return nil, errors.New(fmt.Sprintf("Key '%s' is not known to cache", hashValue))
// 	}

// 	sigolo.Debug("Cache has key '%s'", hashValue)

// 	// Key is known, but not loaded into RAM
// 	if content == nil {
// 		sigolo.Debug("Cache has content for '%s' already loaded", hashValue)

// 		content, err := ioutil.ReadFile(c.folder + hashValue)
// 		if err != nil {
// 			sigolo.Error("Error reading cached file '%s': %s", hashValue, err)
// 			return nil, err
// 		}

// 		c.mutex.Lock()
// 		c.knownValues[hashValue] = content
// 		c.mutex.Unlock()
// 	}

//		return content, nil
//	}
// func get(url string) ([]byte, error) {
// 	response, err := http.Get(url)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer response.Body.Close()

// 	content, err := ioutil.ReadAll(response.Body)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return content, nil
// }

// proxy is used to perform a proxied request.
type proxy struct {
	client    http.Client
	proxyList []string
}

// NewProxy returns a new Proxy with an (optionally pre-configured) http client.
func New(client http.Client, proxyList []string) *proxy {
	return &proxy{client: client, proxyList: proxyList}
}

func handleError(err error, w http.ResponseWriter) {
	fmt.Println(err.Error())
	w.WriteHeader(500)
	fmt.Fprintf(w, err.Error())
}
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// Request decorates http.Client.Do() by adding the given proxy configuration to the request.
func (p *proxy) Request(
	request http.Request, proxyURL url.URL, proxyUser string, proxyPassword string,
) (*http.Response, error) {
	header := http.Header{}

	auth := fmt.Sprintf("%s:%s", proxyUser, proxyPassword)
	basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
	header.Add(authorizationHeader, basicAuth)
	// log.Fatal(header)

	p.client.Transport = &http.Transport{
		Proxy:              http.ProxyURL(&proxyURL),
		ProxyConnectHeader: header,
	}

	return p.client.Do(&request)
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Println(r.RemoteAddr, " ", r.Method, " ", r.URL)
	if r.URL.Scheme == `` {
		if r.URL.Port() == `443` {
			r.URL.Scheme = "https"
			r.URL.Host = r.URL.Hostname()
		} else {
			r.URL.Scheme = "http"
		}
	}

	fullUrl := r.URL.String()
	fmt.Println(fullUrl)

	// client := &http.Client{}

	// resp, err := client.Do(r)
	// if err != nil {
	// 	http.Error(w, "Server Error", http.StatusInternalServerError)
	// 	log.Fatal("ServeHTTP:", err)
	// }
	// defer resp.Body.Close()
	// log.Println(r.RemoteAddr, " ", resp.Status)
	// Use the same proxy configuration for all incoming requests.
	// if len(p.proxyList) == 0 {
	// 	http.Error(w, "Proxy list is empty", http.StatusInternalServerError)
	// 	return
	// }
	// proxyURL, _ := url.Parse(p.proxyList[0]) // Assuming the first proxy from the list.

	proxyUser := "bompjrcx"
	proxyPass := "knwc76w8glgs"
	proxyURI, _ := url.Parse("http://bompjrcx:knwc76w8glgs@38.154.227.167:5868")
	// proxyURI, _ := url.Parse("http://38.154.227.167:5868")

	// URL to make proxied request to.
	targetURL := "http://httpbin.org/ip"

	// Create your request as normal.
	request, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		log.Fatal("Error creating request:", err)
	}

	// Initialize gowebshareproxy.
	proxysa := New(http.Client{}, []string{})

	// Make the proxied request.
	res, err := proxysa.Request(*request, *proxyURI, proxyUser, proxyPass)
	if err != nil {
		log.Fatal("Error making proxied request:", err)
	}
	defer res.Body.Close()

	// Check the response status code.
	if res.StatusCode != http.StatusOK {
		log.Fatalf("Unexpected response status code: %d", res.StatusCode)
	}

	// if r.Method == http.MethodGet {
	// 	fmt.Println(fullUrl)
	// 	content, err := get(fullUrl)
	// 	if err != nil {
	// 		handleError(err, w)
	// 	} else {
	// 		w.Write(content)
	// 	}
	// }

	// log.Println("Proxied request successful.")

	// Copy headers from the proxied response to the response writer.
	for key, values := range res.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Copy the status code from the proxied response.
	w.WriteHeader(res.StatusCode)
	// client := http.Client{}
	// resp, err := client.Do(r)
	// if err != nil {
	// 	http.Error(w, "Server Error", http.StatusInternalServerError)
	// 	log.Fatal("ServeHTTP:", err)
	// }

	// Copy the body from the proxied response to the response writer.
	// copyHeader(w.Header(), resp.Header)
	_, err = io.Copy(w, res.Body)
	if err != nil {
		log.Println("Error copying response body:", err)
	}
}

func main() {

	var addr = flag.String("addr", "127.0.0.1:8080", "The addr of the application.")
	flag.Parse()

	handler := &proxy{}

	log.Println("Starting proxy server on", *addr)
	if err := http.ListenAndServe(*addr, handler); err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}
