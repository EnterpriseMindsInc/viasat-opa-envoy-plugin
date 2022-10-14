package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	//"github.com/golang/protobuf/ptypes/wrappers"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	pb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/open-policy-agent/opa/rego"
)

var (
	grpcport = flag.String("grpcport", "192.168.163.1:18080", "grpcport")
	hs       *health.Server
)

type server struct{}

type healthServer struct{}

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

type ExternalData struct {
	PartnerUsages interface{} `json:"partner_usages"`
}

type JsonResponse struct {
	Data         Data         `json:"data"`
	Success      bool         `json:"success"`
	Message      string       `json:"message"`
	ExternalData ExternalData `json:"external_data"`
}

// To keep policies in memory
var jsonData JsonResponse

func (s *healthServer) Check(ctx context.Context, in *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	log.Printf("Handling grpc Check request + %s", in.String())
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

func (s *healthServer) Watch(in *healthpb.HealthCheckRequest, srv healthpb.Health_WatchServer) error {
	return status.Error(codes.Unimplemented, "Watch is not implemented")
}

func (s *server) Process(srv pb.ExternalProcessor_ProcessServer) error {

	ctx := srv.Context()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		req, err := srv.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return status.Errorf(codes.Unknown, "cannot receive stream request: %v", err)
		}
		resp := &pb.ProcessingResponse{}
		switch v := req.Request.(type) {
		case *pb.ProcessingRequest_ResponseHeaders:
			log.Printf("pb.ProcessingRequest_ResponseHeaders %v \n", v)
			r := req.Request
			h := r.(*pb.ProcessingRequest_ResponseHeaders)

			//Pick the role to apply
			role := "internal"
			//Check Role and Imposing Policies
			resp = imposePolicies(ctx, role, r, h)
			break

		case *pb.ProcessingRequest_ResponseBody:
			r := req.Request
			h := r.(*pb.ProcessingRequest_ResponseBody)
			log.Printf("pb.ProcessingRequest_ResponseBody %v \n", h)
			break
		}
		if err := srv.Send(resp); err != nil {
			log.Printf("send error %v", err)

		}
	}
}

// Imposing the policies
func imposePolicies(ctx context.Context, role string, req interface{}, h *pb.ProcessingRequest_ResponseHeaders) *pb.ProcessingResponse {

	//Headers to remove and add
	var headersToRemove []string
	var headersToAdd = make(http.Header)

	// resp := &pb.ProcessingResponse{}
	//check outbound policies for the role
	for i := 0; i < len(jsonData.Data.Environments.Roles); i++ {
		// if strings.ToLower(role) == strings.ToLower(jsonData.Data.Environments.Roles[i].Title) {
		for j := 0; j < len(jsonData.Data.Environments.Roles[i].Apis); j++ {
			log.Default().Printf("DEBUG-1:::::")
			// if strings.ToLower("/order/create") == strings.ToLower(jsonData.Data.Environments.Roles[i].Apis[j].EndPoint) {
			for z := 0; z < len(jsonData.Data.Environments.Roles[i].Apis[j].Policies); z++ {
				log.Default().Printf("DEBUG-2:::::" + strings.ToLower(jsonData.Data.Environments.Roles[i].Apis[j].Policies[z].Type))
				if strings.ToLower(jsonData.Data.Environments.Roles[i].Apis[j].Policies[z].Type) == strings.ToLower("OUTBOUND") {
					output := evaluateRego(ctx, jsonData.Data.Environments.Roles[i].Apis[j].Policies[z].Rego, req)
					jsonMap := output.(map[string]interface{})
					if _, ok := jsonMap["allow"].(bool); ok {
						if value, ok := jsonMap["request_headers_to_remove"]; ok {
							headerMap := value.(map[string]interface{})
							for k, _ := range headerMap {
								headersToRemove = append(headersToRemove, k)
								log.Default().Printf(k)
							}
						}
						if value, ok := jsonMap["request_headers_to_add"]; ok {
							headerMap := value.(map[string]interface{})
							transformToHTTPHeaderFormat(headerMap, &headersToAdd)
						}
					}

				}
			}
			rhq := &pb.HeadersResponse{
				Response: &pb.CommonResponse{
					HeaderMutation: &pb.HeaderMutation{
						RemoveHeaders: headersToRemove,
						SetHeaders:    transformHTTPHeaderToEnvoyHeaderValueOption(headersToAdd),
					},
				},
			}
			resp := &pb.ProcessingResponse{
				Response: &pb.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: rhq,
				},
			}
			return resp
			// }
		}
		// }
	}
	return nil
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
func transformHTTPHeaderToEnvoyHeaderValueOption(headers http.Header) []*corev3.HeaderValueOption {
	responseHeaders := []*corev3.HeaderValueOption{}

	for key, values := range headers {
		for idx := range values {
			headerValue := &corev3.HeaderValue{
				Key:   key,
				Value: values[idx],
			}
			headerValueOption := &corev3.HeaderValueOption{
				Header: headerValue,
			}
			responseHeaders = append(responseHeaders, headerValueOption)
		}
	}

	return responseHeaders
}

func main() {

	//Sync polices from Sync Service
	syncService := "http://a1bb788e879764d0bb879810e815b1b3-1271484013.us-east-1.elb.amazonaws.com:3001/api/sync-service/v1/entitlements/qa"
	response, err := http.Get(syncService)
	if err != nil {
		fmt.Print(err.Error())
		os.Exit(1)
	}
	responseData, _ := ioutil.ReadAll(response.Body)
	log.Default().Printf(string(responseData))
	json.Unmarshal([]byte(responseData), &jsonData)
	//calling sync service based on configurable interval
	ticker := time.NewTicker(time.Duration(10) * time.Second)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				response, err := http.Get(syncService)
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

	flag.Parse()

	lis, err := net.Listen("tcp", *grpcport)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	sopts := []grpc.ServerOption{grpc.MaxConcurrentStreams(1000)}
	s := grpc.NewServer(sopts...)

	pb.RegisterExternalProcessorServer(s, &server{})
	healthpb.RegisterHealthServer(s, &healthServer{})

	log.Printf("Starting gRPC server on port %s\n", *grpcport)

	var gracefulStop = make(chan os.Signal)
	signal.Notify(gracefulStop, syscall.SIGTERM)
	signal.Notify(gracefulStop, syscall.SIGINT)
	go func() {
		sig := <-gracefulStop
		log.Printf("caught sig: %+v", sig)
		log.Println("Wait for 1 second to finish processing")
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}()
	s.Serve(lis)
}
