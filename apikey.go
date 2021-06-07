package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
)

const (
	authPrefix = "ApiKey "
)

var AuthKey = http.CanonicalHeaderKey("Authorization")

type ApiKey struct {
	Id  string
	Key string
}

func (k ApiKey) Token() string {
	s := fmt.Sprintf("%s:%s", k.Id, k.Key)
	return base64.StdEncoding.EncodeToString([]byte(s))
}

const ManagedByFleetServer = "fleet-server"

type Type int

const (
	TypeAccess Type = iota
	TypeOutput
)

func (t Type) String() string {
	return []string{"access", "output"}[t]
}

type Metadata struct {
	AgentId   string `json:"agent_id,omitempty"`
	Managed   bool   `json:"managed,omitempty"`
	ManagedBy string `json:"managed_by,omitempty"`
	Type      string `json:"type,omitempty"`
}

func NewMetadata(agentId string, typ Type) Metadata {
	return Metadata{
		AgentId:   agentId,
		Managed:   true,
		ManagedBy: ManagedByFleetServer,
		Type:      typ.String(),
	}
}

type SecurityInfo struct {
	UserName    string            `json:"username"`
	Roles       []string          `json:"roles"`
	FullName    string            `json:"full_name"`
	Email       string            `json:"email"`
	Metadata    json.RawMessage   `json:"metadata"`
	Enabled     bool              `json:"enabled"`
	AuthRealm   map[string]string `json:"authentication_realm"`
	LookupRealm map[string]string `json:"lookup_realm"`
}

// Note: Prefer the bulk wrapper on this API
func (k ApiKey) Authenticate(ctx context.Context, es *elasticsearch.Client) (*SecurityInfo, error) {

	token := fmt.Sprintf("%s%s", authPrefix, k.Token())

	req := esapi.SecurityAuthenticateRequest{
		Header: map[string][]string{AuthKey: []string{token}},
	}

	res, err := req.Do(ctx, es)

	if err != nil {
		return nil, fmt.Errorf("apikey auth request %s: %w", k.Id, err)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	if res.IsError() {
		return nil, fmt.Errorf("apikey auth response %s: %s", k.Id, res.String())
	}

	var info SecurityInfo
	decoder := json.NewDecoder(res.Body)
	if err := decoder.Decode(&info); err != nil {
		return nil, fmt.Errorf("apikey auth parse %s: %w", k.Id, err)
	}

	return &info, nil
}

func Create(ctx context.Context, client *elasticsearch.Client, name, ttl string, roles []byte, meta interface{}) (*ApiKey, error) {
	payload := struct {
		Name       string          `json:"name,omitempty"`
		Expiration string          `json:"expiration,omitempty"`
		Roles      json.RawMessage `json:"role_descriptors,omitempty"`
		Metadata   interface{}     `json:"metadata"`
	}{
		Name:       name,
		Expiration: ttl,
		Roles:      roles,
		Metadata:   meta,
	}

	body, err := json.Marshal(&payload)
	if err != nil {
		return nil, err
	}

	opts := []func(*esapi.SecurityCreateAPIKeyRequest){
		client.Security.CreateAPIKey.WithContext(ctx),
		client.Security.CreateAPIKey.WithRefresh("true"),
	}

	res, err := client.Security.CreateAPIKey(
		bytes.NewReader(body),
		opts...,
	)

	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("fail CreateAPIKey: %s", res.String())
	}

	type APIKeyResponse struct {
		Id         string `json:"id"`
		Name       string `json:"name"`
		Expiration uint64 `json:"expiration"`
		ApiKey     string `json:"api_key"`
	}

	var resp APIKeyResponse
	d := json.NewDecoder(res.Body)
	if err = d.Decode(&resp); err != nil {
		return nil, err
	}

	key := ApiKey{
		Id:  resp.Id,
		Key: resp.ApiKey,
	}

	return &key, err
}

type InfoResponse struct {
	ClusterName string `json:"cluster_name"`
	ClusterUUID string `json:"cluster_uuid"`
	Version     struct {
		Number string `json:"number"`
	} `json:"version"`
}

func info(ctx context.Context, es *elasticsearch.Client) (*InfoResponse, error) {
	// Validate the connection
	res, err := es.Info()

	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("info fail %v", res)
	}

	var resp InfoResponse

	d := json.NewDecoder(res.Body)
	if err = d.Decode(&resp); err != nil {
		return nil, err
	}

	return &resp, err
}

func makeClient(url, user, pass string, nconns int) (*elasticsearch.Client, error) {

	// build the transport from the config
	httpTransport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		DisableKeepAlives:     false,
		DisableCompression:    false,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   32,
		MaxConnsPerHost:       nconns,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: time.Minute,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Create a elastic cluster client
	cfg := elasticsearch.Config{
		Addresses: []string{url},
		Username:  user,
		Password:  pass,
		Transport: httpTransport,
	}

	es, err := elasticsearch.NewClient(cfg)

	if err != nil {
		fmt.Printf("Fail create elastic client: %v\n", err)
		return nil, err
	}

	info, err := info(context.Background(), es)
	if err != nil {
		fmt.Printf("Fail connect elastic client: %v\n", err)
		return nil, err
	}

	fmt.Printf(
		"Connected elasticsearch %s version:%s\n",
		info.ClusterName,
		info.Version.Number,
	)

	return es, err
}

const kFleetAccessRolesJSON = `
{
	"fleet-apikey-access": {
		"cluster": [],
		"applications": [{
			"application": ".fleet",
			"privileges": ["no-privileges"],
			"resources": ["*"]
		}]
	}
}
`

// Create a go routine for each connection, generate a key unil we hit nconns
func createKeys(es *elasticsearch.Client, nconns, nkeys int) ([]ApiKey, error) {

	inCh := make(chan string, nkeys)
	outCh := make(chan ApiKey, 1024)

	defer close(inCh)

	fmt.Printf("Generating %d keys using %d connections\n", nkeys, nconns)

	// create the subroutines
	for i := 0; i < nconns; i++ {

		go func() {

			for name := range inCh {
				key, err := Create(
					context.Background(),
					es,
					name,
					"60m",
					[]byte(kFleetAccessRolesJSON),
					NewMetadata(name, TypeAccess),
				)

				if err != nil {
					panic(err)
				}

				outCh <- *key
			}

		}()
	}

	// fill the pipe
	for i := 0; i < nkeys; i++ {
		inCh <- fmt.Sprintf("key_%i", i)
	}

	// wait for results
	keys := make([]ApiKey, 0, nkeys)

	last := time.Now()
	for i := 1; i <= nkeys; i++ {
		key := <-outCh
		keys = append(keys, key)
		if i%500 == 0 || time.Since(last) >= (time.Second*5) {
			fmt.Printf("%v %v/%v\n", time.Now().Format("3:04:05PM"), i, nkeys)
			last = time.Now()
		}
	}

	return keys, nil
}

// Using all nconns, authenticate as quickly as possible.
func burstAuth(es *elasticsearch.Client, keys []ApiKey, nconns int) error {
	nkeys := len(keys)

	inCh := make(chan ApiKey, nkeys)
	outCh := make(chan SecurityInfo, 1024)

	defer close(inCh)

	fmt.Printf("Authenticating %d keys using %d connections\n", nkeys, nconns)

	// create the subroutines
	for i := 0; i < nconns; i++ {

		go func() {

			for key := range inCh {

				info, err := key.Authenticate(context.Background(), es)

				if err != nil {
					panic(err)
				}

				outCh <- *info
			}

		}()
	}

	// fill the pipe
	for _, key := range keys {
		inCh <- key
	}

	// wait for results

	last := time.Now()
	for i := 1; i <= nkeys; i++ {
		<-outCh
		if i%500 == 0 || time.Since(last) >= (time.Second*5) {
			fmt.Printf("%v %v/%v\n", time.Now().Format("3:04:05PM"), i, nkeys)
			last = time.Now()
		}
	}

	return nil
}

func main() {
	var nkeys int
	var nconns int
	flag.IntVar(&nkeys, "n", 100000, "number of api keys to create")
	flag.IntVar(&nconns, "c", 128, "number of connections")
	flag.Usage = func() {
		fmt.Println("usage: apikey [-n nkeys] [-c nconns] url username password")
	}
	flag.Parse()

	if len(flag.Args()) != 3 {
		flag.Usage()
		os.Exit(-1)
	}

	es, err := makeClient(flag.Arg(0), flag.Arg(1), flag.Arg(2), nconns)
	if err != nil {
		os.Exit(-1)
	}

	start := time.Now()
	keys, err := createKeys(es, nconns, nkeys)
	if err != nil {
		os.Exit(-1)
	}

	tdiff := time.Since(start)
	fmt.Printf("Create %d keys in %v.  Average: %v\n", len(keys), tdiff, tdiff/time.Duration(len(keys)))

	nBursts := 5
	for i := 0; i < nBursts; i++ {
		fmt.Printf("-----Burst Auth Pass %d/%d\n", i+1, nBursts)
		start = time.Now()
		err = burstAuth(es, keys, nconns)
		if err != nil {
			os.Exit(-1)
		}

		tdiff = time.Since(start)
		fmt.Printf("Auth %d keys in %v.  Average: %v\n", len(keys), tdiff, tdiff/time.Duration(len(keys)))
	}

}
