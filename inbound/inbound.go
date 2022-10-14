// Package auth implements the custom logic to do precheck
// filter the request with Rego
// fork from open-policy-agent/opa-envoy-plugin repo
// Author: Dinesh Sinnarasse, Enterprise Inc.

package inbound

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	ext_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_authz_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/genproto/googleapis/rpc/code"
	rpc_status "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/reflect/protoregistry"
	"gopkg.in/square/go-jose.v2/jwt"

	internal_util "github.com/open-policy-agent/opa-envoy-plugin/internal/util"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/logging"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	iCache "github.com/open-policy-agent/opa/topdown/cache"
	"github.com/open-policy-agent/opa/util"
)

const defaultAddr = ":9191"
const defaultPath = "envoy/authz/allow"
const defaultDryRun = false
const defaultEnableReflection = false
const defaultSyncServiceAddr = "http://localhost:8080/entitlements"
const defaultTimeInterval = 5 //Seconds

// Those are the defaults from grpc-go.
// See https://github.com/grpc/grpc-go/blob/master/server.go#L58 for more details.
const defaultGRPCServerMaxReceiveMessageSize = 1024 * 1024 * 4
const defaultGRPCServerMaxSendMessageSize = math.MaxInt32

// PluginName is the name to register with the OPA plugin manager
const PluginName = "custom_auth_grpc"

// Struct : Environments, Roles, Policies, APIs, Authors
// to map sync service data

type APIPolicy struct {
	ID        int         `json:"id"`
	APIID     int         `json:"api_id"`
	PolicyID  int         `json:"policy_id"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
	DeletedAt interface{} `json:"deleted_at"`
}

type Policies struct {
	ID           int         `json:"id"`
	Title        string      `json:"title"`
	PolicyUUID   string      `json:"policy_uuid"`
	Rego         string      `json:"rego"`
	FormatedRego string      `json:"formated_rego"`
	Purpose      interface{} `json:"purpose"`
	Type         string      `json:"type"`
	Status       string      `json:"status"`
	AuthorID     int         `json:"author_id"`
	ApproverID   interface{} `json:"approver_id"`
	CreatedAt    time.Time   `json:"created_at"`
	UpdatedAt    time.Time   `json:"updated_at"`
	DeletedAt    interface{} `json:"deleted_at"`
	APIPolicy    APIPolicy   `json:"ApiPolicy"`
}

type Apis struct {
	ID        int         `json:"id"`
	EndPoint  string      `json:"end_point"`
	Title     string      `json:"title"`
	Purpose   string      `json:"purpose"`
	Method    string      `json:"method"`
	Status    string      `json:"status"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
	DeletedAt interface{} `json:"deleted_at"`
	Policies  []Policies  `json:"policies"`
}

type Partners struct {
	ID        int         `json:"id"`
	Title     string      `json:"title"`
	PartyID   string      `json:"party_id"`
	Phone     string      `json:"phone"`
	Email     string      `json:"email"`
	RoleID    int         `json:"role_id"`
	Status    string      `json:"status"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
	DeletedAt interface{} `json:"deleted_at"`
}

type Roles struct {
	ID        int         `json:"id"`
	Title     string      `json:"title"`
	Purpose   string      `json:"purpose"`
	Status    string      `json:"status"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
	DeletedAt interface{} `json:"deleted_at"`
	Partners  []Partners  `json:"partners"`
	Apis      []Apis      `json:"apis"`
}

type Environments struct {
	ID        int         `json:"id"`
	Title     string      `json:"title"`
	Purpose   string      `json:"purpose"`
	BaseURL   string      `json:"base_url"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
	DeletedAt interface{} `json:"deleted_at"`
	Roles     []Roles     `json:"roles"`
}

type Data struct {
	Environments Environments `json:"environments"`
}

type JsonResponse struct {
	Data         Data         `json:"data"`
	Success      bool         `json:"success"`
	Message      string       `json:"message"`
	ExternalData ExternalData `json:"external_data"`
}

type ExternalData struct {
	PartnerUsages interface{} `json:"partner_usages"`
}

// To keep policies in memory
var jsonData JsonResponse

// Validate receives a slice of bytes representing the plugin's
// configuration and returns a configuration value that can be used to
// instantiate the plugin.
func Validate(m *plugins.Manager, bs []byte) (*Config, error) {

	cfg := Config{
		Addr:               defaultAddr,
		DryRun:             defaultDryRun,
		EnableReflection:   defaultEnableReflection,
		GRPCMaxRecvMsgSize: defaultGRPCServerMaxReceiveMessageSize,
		GRPCMaxSendMsgSize: defaultGRPCServerMaxSendMessageSize,
		SyncServiceAddr:    defaultSyncServiceAddr,
		SyncInterval:       defaultTimeInterval,
	}

	if err := util.Unmarshal(bs, &cfg); err != nil {
		return nil, err
	}

	if cfg.Path != "" && cfg.Query != "" {
		return nil, fmt.Errorf("invalid config: specify a value for only the \"path\" field")
	}

	var parsedQuery ast.Body
	var err error

	if cfg.Query != "" {
		// Deprecated: Use Path instead
		parsedQuery, err = ast.ParseBody(cfg.Query)
	} else {
		if cfg.Path == "" {
			cfg.Path = defaultPath
		}
		path := stringPathToDataRef(cfg.Path)
		parsedQuery, err = ast.ParseBody(path.String())
	}

	if err != nil {
		return nil, err
	}

	cfg.parsedQuery = parsedQuery

	if cfg.ProtoDescriptor != "" {
		ps, err := internal_util.ReadProtoSet(cfg.ProtoDescriptor)
		if err != nil {
			return nil, err
		}
		cfg.protoSet = ps
	}

	return &cfg, nil
}

// New returns a Plugin that implements the Envoy ext_authz API.
func New(m *plugins.Manager, cfg *Config) plugins.Plugin {

	plugin := &envoyExtAuthzGrpcServer{
		manager: m,
		cfg:     *cfg,
		server: grpc.NewServer(
			grpc.MaxRecvMsgSize(cfg.GRPCMaxRecvMsgSize),
			grpc.MaxSendMsgSize(cfg.GRPCMaxSendMsgSize),
		),
		preparedQueryDoOnce:    new(sync.Once),
		interQueryBuiltinCache: iCache.NewInterQueryCache(m.InterQueryBuiltinCacheConfig()),
	}

	// Register Authorization Server
	ext_authz_v3.RegisterAuthorizationServer(plugin.server, plugin)

	m.RegisterCompilerTrigger(plugin.compilerUpdated)

	// Register reflection service on gRPC server
	if cfg.EnableReflection {
		reflection.Register(plugin.server)
	}

	m.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})

	return plugin
}

// Config represents the plugin configuration.
type Config struct {
	Addr               string `json:"addr"`
	Query              string `json:"query"` // Deprecated: Use Path instead
	Path               string `json:"path"`
	DryRun             bool   `json:"dry-run"`
	EnableReflection   bool   `json:"enable-reflection"`
	parsedQuery        ast.Body
	ProtoDescriptor    string `json:"proto-descriptor"`
	protoSet           *protoregistry.Files
	GRPCMaxRecvMsgSize int    `json:"grpc-max-recv-msg-size"`
	GRPCMaxSendMsgSize int    `json:"grpc-max-send-msg-size"`
	SyncServiceAddr    string `json:"syncservice-addr"`
	SyncInterval       int    `json:"sync-time-interval"`
}

type envoyExtAuthzGrpcServer struct {
	cfg                    Config
	server                 *grpc.Server
	manager                *plugins.Manager
	preparedQuery          *rego.PreparedEvalQuery
	preparedQueryDoOnce    *sync.Once
	interQueryBuiltinCache iCache.InterQueryCache
}

type envoyExtAuthzV2Wrapper struct {
	v3 *envoyExtAuthzGrpcServer
}

func (p *envoyExtAuthzGrpcServer) ParsedQuery() ast.Body {
	return p.cfg.parsedQuery
}

func (p *envoyExtAuthzGrpcServer) Store() storage.Store {
	return p.manager.Store
}

func (p *envoyExtAuthzGrpcServer) Compiler() *ast.Compiler {
	return p.manager.GetCompiler()
}

func (p *envoyExtAuthzGrpcServer) Runtime() *ast.Term {
	return p.manager.Info
}

func (p *envoyExtAuthzGrpcServer) PreparedQueryDoOnce() *sync.Once {
	return p.preparedQueryDoOnce
}

func (p *envoyExtAuthzGrpcServer) InterQueryBuiltinCache() iCache.InterQueryCache {
	return p.interQueryBuiltinCache
}

func (p *envoyExtAuthzGrpcServer) PreparedQuery() *rego.PreparedEvalQuery {
	return p.preparedQuery
}

func (p *envoyExtAuthzGrpcServer) SetPreparedQuery(pq *rego.PreparedEvalQuery) {
	p.preparedQuery = pq
}

func (p *envoyExtAuthzGrpcServer) Logger() logging.Logger {
	return p.manager.Logger()
}

func (p *envoyExtAuthzGrpcServer) Start(ctx context.Context) error {
	//calling sync service first time
	response, err := http.Get(p.cfg.SyncServiceAddr)
	if err != nil {
		fmt.Print(err.Error())
		os.Exit(1)
	}
	responseData, _ := ioutil.ReadAll(response.Body)
	log.Default().Printf(string(responseData))
	json.Unmarshal([]byte(responseData), &jsonData)
	//calling sync service based on configurable interval
	ticker := time.NewTicker(time.Duration(p.cfg.SyncInterval) * time.Second)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				response, err := http.Get(p.cfg.SyncServiceAddr)
				if err != nil {
					fmt.Print(err.Error())
					os.Exit(1)
				}
				responseData, _ := ioutil.ReadAll(response.Body)
				log.Default().Printf("Called sync service to pull updated policies")
				json.Unmarshal([]byte(responseData), &jsonData)
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()

	log.Default().Printf("Reading Policies from Sync Service :" + jsonData.Data.Environments.BaseURL)
	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})
	go p.listen()
	return nil
}

func (p *envoyExtAuthzGrpcServer) Stop(ctx context.Context) {
	p.server.Stop()
	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})
}

func (p *envoyExtAuthzGrpcServer) Reconfigure(ctx context.Context, config interface{}) {
	return
}

func (p *envoyExtAuthzGrpcServer) compilerUpdated(txn storage.Transaction) {
	p.preparedQueryDoOnce = new(sync.Once)
}

func (p *envoyExtAuthzGrpcServer) listen() {
	logger := p.manager.Logger()
	addr := p.cfg.Addr
	if !strings.Contains(addr, "://") {
		addr = "grpc://" + addr
	}

	parsedURL, err := url.Parse(addr)
	if err != nil {
		logger.WithFields(map[string]interface{}{"err": err}).Error("Unable to parse url.")
		return
	}

	// The listener is closed automatically by Serve when it returns.
	var l net.Listener

	switch parsedURL.Scheme {
	case "unix":
		socketPath := parsedURL.Host + parsedURL.Path
		// Recover @ prefix for abstract Unix sockets.
		if strings.HasPrefix(parsedURL.String(), parsedURL.Scheme+"://@") {
			socketPath = "@" + socketPath
		} else {
			// Remove domain socket file in case it already exists.
			os.Remove(socketPath)
		}
		l, err = net.Listen("unix", socketPath)
	case "grpc":
		l, err = net.Listen("tcp", parsedURL.Host)
	default:
		err = fmt.Errorf("invalid url scheme %q", parsedURL.Scheme)
	}

	if err != nil {
		logger.WithFields(map[string]interface{}{"err": err}).Error("Unable to create listener.")
	}

	logger.WithFields(map[string]interface{}{
		"addr":              p.cfg.Addr,
		"query":             p.cfg.Query,
		"path":              p.cfg.Path,
		"dry-run":           p.cfg.DryRun,
		"enable-reflection": p.cfg.EnableReflection,
	}).Info("Starting gRPC server.")

	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateOK})

	if err := p.server.Serve(l); err != nil {
		logger.WithFields(map[string]interface{}{"err": err}).Error("Listener failed.")
		return
	}

	logger.Info("Listener exited.")
	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})
}

// Check is envoy.service.auth.v3.Authorization/Check
func (p *envoyExtAuthzGrpcServer) Check(ctx context.Context, req *ext_authz_v3.CheckRequest) (*ext_authz_v3.CheckResponse, error) {
	//Precheck and policy for inbound policy
	respV3, err := preCheckHeader(req, ctx)

	if err != nil {
		log.Default().Printf("Panic: something went wrong")
	}
	//Returning response to upstream cluster
	return respV3, nil
}

func stringPathToDataRef(s string) (r ast.Ref) {
	result := ast.Ref{ast.DefaultRootDocument}
	result = append(result, stringPathToRef(s)...)
	return result
}

func stringPathToRef(s string) (r ast.Ref) {
	if len(s) == 0 {
		return r
	}

	p := strings.Split(s, "/")
	for _, x := range p {
		if x == "" {
			continue
		}

		i, err := strconv.Atoi(x)
		if err != nil {
			r = append(r, ast.StringTerm(x))
		} else {
			r = append(r, ast.IntNumberTerm(i))
		}
	}
	return r
}

// Precheck and validate inbound policies
func preCheckHeader(req *ext_authz_v3.CheckRequest, ctx context.Context) (*ext_authz_v3.CheckResponse, error) {
	respV3 := &ext_authz_v3.CheckResponse{}
	log.Default().Printf(respV3.GetDynamicMetadata().String())

	//Headers to remove and add
	var headersToAdd = make(http.Header)
	var headersToRemove []string
	// var customResoponseHeader = make(http.Header)

	//JWT Claim
	var claims map[string]interface{}
	_, ok := req.GetAttributes().GetRequest().GetHttp().GetHeaders()["authorization"]
	if !ok {
		log.Default().Println("The request is not Authorized,does not have proper authorization parameters")
		status := int32(code.Code_PERMISSION_DENIED)
		respV3.Status = &rpc_status.Status{Code: status}
		return respV3, nil
	}
	tokenString := strings.Split(req.GetAttributes().GetRequest().GetHttp().GetHeaders()["authorization"], " ")[1]
	token, _ := jwt.ParseSigned(tokenString)
	_ = token.UnsafeClaimsWithoutVerification(&claims)
	role := claims["role"].(string)
	//setting role in custom header
	// customResoponseHeader.Add("x-powered-by", role)

	//Validation Process
	for i := 0; i < len(jsonData.Data.Environments.Roles); i++ {
		if strings.ToLower(role) == strings.ToLower(jsonData.Data.Environments.Roles[i].Title) {
			for j := 0; j < len(jsonData.Data.Environments.Roles[i].Apis); j++ {
				if req.GetAttributes().Request.Http.Method == jsonData.Data.Environments.Roles[i].Apis[j].Method &&
					req.GetAttributes().Request.Http.Path == jsonData.Data.Environments.Roles[i].Apis[j].EndPoint {
					//Setting methiod and endpoint in custom header
					// customResoponseHeader.Add("x-user-header-method", req.GetAttributes().Request.Http.Method)
					// customResoponseHeader.Add("x-user-header-endpoint", req.GetAttributes().Request.Http.Path)
					for z := 0; z < len(jsonData.Data.Environments.Roles[i].Apis[j].Policies); z++ {
						if strings.ToLower(jsonData.Data.Environments.Roles[i].Apis[j].Policies[z].Type) == strings.ToLower("INBOUND") {
							log.Default().Printf("DEBUG::: Rego checking")
							output := evaluateRego(ctx, jsonData.Data.Environments.Roles[i].Apis[j].Policies[z].Rego, req)
							jsonMap := output.(map[string]interface{})
							if b, _ := jsonMap["allow"].(bool); !b {
								log.Default().Printf("The request is rejected based on the policies")
								status := int32(code.Code_PERMISSION_DENIED)
								respV3.Status = &rpc_status.Status{Code: status}
								return respV3, nil
							} else {
								if value, ok := jsonMap["request_headers_to_remove"]; ok {
									headerMap := value.(map[string]interface{})
									for k, _ := range headerMap {
										headersToRemove = append(headersToRemove, k)
									}
									log.Default().Println(headersToRemove)
								}
								if value, ok := jsonMap["request_headers_to_add"]; ok {
									transformToHTTPHeaderFormat(value, &headersToAdd)
								}
							}
						}
					}
					log.Default().Println("The request is authorized to access the endpoint")
					status := int32(code.Code_OK)
					respV3.Status = &rpc_status.Status{Code: status}
					finalHeaderToAdd, _ := transformHTTPHeaderToEnvoyHeaderValueOption(headersToAdd)
					// customHeadertoAddInResponse, _ := transformHTTPHeaderToEnvoyHeaderValueOption(customResoponseHeader)
					respV3.HttpResponse = &ext_authz_v3.CheckResponse_OkResponse{
						OkResponse: &ext_authz_v3.OkHttpResponse{
							HeadersToRemove: headersToRemove,
							Headers:         finalHeaderToAdd,
							// ResponseHeadersToAdd: customHeadertoAddInResponse,
						},
					}
					return respV3, nil

				}
			}
			log.Default().Println("The request role ", role+" is not authorized to access the endpoint or method")
			status := int32(code.Code_PERMISSION_DENIED)
			respV3.Status = &rpc_status.Status{Code: status}
			return respV3, nil
		}
		log.Default().Println("The request role ", role+" is not authorized to access the environment APIs")
		status := int32(code.Code_PERMISSION_DENIED)
		respV3.Status = &rpc_status.Status{Code: status}
		return respV3, nil
	}
	log.Default().Println("The environemnt does not have any role, Please create a one")
	status := int32(code.Code_PERMISSION_DENIED)
	respV3.Status = &rpc_status.Status{Code: status}
	return respV3, nil
}

// Evaluating the Rego files
func evaluateRego(ctx context.Context, regoToBeCheck string, req interface{}) interface{} {
	// Extracting package name from rego file
	var queryData string
	regoQueryPackage := strings.Split(regoToBeCheck, "\n")
	if regoQueryPackage != nil {
		tempVar := strings.Split(regoQueryPackage[0], " ")
		if tempVar != nil {
			queryData = "data." + tempVar[1]
		}
		log.Default().Printf("Package name of the Rego files " + queryData)
	}
	//Creating new rego from rego String
	rego := rego.New(
		rego.Query(queryData),
		rego.Module("example.rego",
			regoToBeCheck,
		),
		rego.Input(req),
	)
	// Run evaluation.
	rs, err := rego.Eval(ctx)
	response, _ := json.Marshal(rs)
	log.Default().Printf(string(response))
	if err != nil {
		panic(err)
	}
	return rs[0].Expressions[0].Value
}

// Convert header string to http Header
func transformToHTTPHeaderFormat(input interface{}, result *http.Header) error {

	takeResponseHeaders := func(headers map[string]interface{}, targetHeaders *http.Header) error {
		for key, value := range headers {
			var headerVal string
			var ok bool
			if headerVal, ok = value.(string); !ok {
				return fmt.Errorf("type assertion error")
			}

			targetHeaders.Add(key, headerVal)
		}
		return nil
	}

	switch input := input.(type) {
	case []interface{}:
		for _, val := range input {
			headers, ok := val.(map[string]interface{})
			if !ok {
				return fmt.Errorf("type assertion error")
			}

			err := takeResponseHeaders(headers, result)
			if err != nil {
				return err
			}
		}

	case map[string]interface{}:
		err := takeResponseHeaders(input, result)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("type assertion error")
	}

	return nil
}

// Convert http Headers to Envoy Header value
func transformHTTPHeaderToEnvoyHeaderValueOption(headers http.Header) ([]*ext_core_v3.HeaderValueOption, error) {
	responseHeaders := []*ext_core_v3.HeaderValueOption{}

	for key, values := range headers {
		for idx := range values {
			headerValue := &ext_core_v3.HeaderValue{
				Key:   key,
				Value: values[idx],
			}
			headerValueOption := &ext_core_v3.HeaderValueOption{
				Header: headerValue,
			}
			responseHeaders = append(responseHeaders, headerValueOption)
		}
	}

	return responseHeaders, nil
}

// Convert http Headers to Envoy Header value
func AddCustomHeaderforOutBoundPolicy(headers http.Header) ([]*ext_core_v3.HeaderValueOption, error) {
	responseHeaders := []*ext_core_v3.HeaderValueOption{}
	for key, values := range headers {
		for idx := range values {
			headerValue := &ext_core_v3.HeaderValue{
				Key:   key,
				Value: values[idx],
			}
			headerValueOption := &ext_core_v3.HeaderValueOption{
				Header: headerValue,
			}
			responseHeaders = append(responseHeaders, headerValueOption)
		}
	}

	return responseHeaders, nil
}
