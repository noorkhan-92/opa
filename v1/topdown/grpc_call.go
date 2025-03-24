package topdown

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/golang/protobuf/jsonpb"
	"github.com/jhump/protoreflect/dynamic"
	"github.com/jhump/protoreflect/dynamic/grpcdynamic"
	"github.com/jhump/protoreflect/grpcreflect"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection/grpc_reflection_v1"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
)

func authInterceptor(token string) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, res interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption) error {

		// Create metadata with Bearer token
		md := metadata.Pairs("authorization", "Bearer "+token)
		ctx = metadata.NewOutgoingContext(ctx, md)

		// Proceed with the call
		return invoker(ctx, method, req, res, cc, opts...)
	}
}

// Keycloak Configuration
var (
	KeycloakTokenURL = os.Getenv("KEYCLOAK_TOKEN_URL")
	ClientID         = os.Getenv("KEYCLOAK_CLIENT_ID")
	ClientSecret     = os.Getenv("KEYCLOAK_CLIENT_SECRET")
)

// Global token source
var (
	tokenSource oauth2.TokenSource
	tokenMutex  sync.Mutex
)

// GetTokenSource initializes and returns a cached token source
func GetTokenSource(ctx context.Context) oauth2.TokenSource {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	// If token source is already created, reuse it
	if tokenSource != nil {
		return tokenSource
	}

	// Create OAuth2 config
	config := clientcredentials.Config{
		ClientID:     ClientID,
		ClientSecret: ClientSecret,
		TokenURL:     KeycloakTokenURL,
		AuthStyle:    oauth2.AuthStyleInParams,
	}

	// Get an initial token and create a reusing token source
	initialToken, err := config.Token(ctx)
	if err != nil {
		log.Fatalf("Failed to fetch initial token: %v", err)
	}

	// Use ReuseTokenSource to refresh token when needed
	tokenSource = oauth2.ReuseTokenSource(initialToken, config.TokenSource(ctx))

	return tokenSource
	return nil
}

func getToken(ctx context.Context) (string, error) {
	ts := GetTokenSource(ctx) // Get the cached token source
	token, err := ts.Token()  // Fetch or refresh the token
	if err != nil {
		return "", fmt.Errorf("failed to retrieve token: %w", err)
	}
	return string(token.AccessToken), nil
}

// custom builtin function for calling grpc service, implements topdown.BuiltinFunc
func builtinGrpcCall(_ BuiltinContext, args []*ast.Term, iter func(*ast.Term) error) error {
	ctx := context.Background()
	// Get the first argument as a string, returning an error if it's not the correct type.
	serverUrl, err := builtins.StringOperand(args[0].Value, 1)
	if err != nil {
		return fmt.Errorf("Failed to retrieve server url: %w", err)
	}
	serviceName, err := builtins.StringOperand(args[1].Value, 2)
	if err != nil {
		return fmt.Errorf("Failed to retrieve service name: %w", err)
	}
	methodName, err := builtins.StringOperand(args[2].Value, 3)
	if err != nil {
		return fmt.Errorf("Failed to retrieve method name: %w", err)
	}
	request, err := builtins.ObjectOperand(args[3].Value, 4)
	if err != nil {
		return fmt.Errorf("Failed to retrieve request: %w", err)
	}

	// grpc reflection
	// connect to the grpc server
	token, err := getToken(ctx)
	if err != nil {
		return fmt.Errorf("Failed to retrieve keycloak token: %w", err)
	}
	conn, err := grpc.NewClient(string(serverUrl), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithUnaryInterceptor(authInterceptor(token)))
	if err != nil {
		return fmt.Errorf("Failed to connect: %w", err)
	defer conn.Close()

	// Create a reflection client to dynamically fetch service descriptors.
	refClient := grpcreflect.NewClientV1(context.Background(), grpc_reflection_v1.NewServerReflectionClient(conn))
	defer refClient.Reset()

	// Resolve the service descriptor dynamically.
	serviceDesc, err := refClient.ResolveService(string(serviceName))
	if err != nil {
		return fmt.Errorf("Failed to resolve service %q: %v", serviceName, err)
	}

	// Find the method descriptor by name.
	methodDesc := serviceDesc.FindMethodByName(string(methodName))
	if methodDesc == nil {
		return fmt.Errorf("Method %q not found in service %q", methodName, serviceName)
	}

	// Create a dynamic stub for making RPC calls.
	stub := grpcdynamic.NewStub(conn)

	// Create a dynamic message for the request.
	reqMsg := dynamic.NewMessage(methodDesc.GetInputType())
	// Set fields on the request. In this example, we set a field "name".
	var jsonMap map[string]interface{}
	if err := ast.As(request, &jsonMap); err != nil {
		return fmt.Errorf("The request %q is not a valid json: %v", request.String(), err)
	}

	for key, value := range jsonMap {
		if err := reqMsg.TrySetFieldByName(key, value); err != nil {
			return fmt.Errorf("Failed to set field: %v", err)
		}
	}

	// Prepare context with a timeout.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Invoke the RPC dynamically using the method descriptor.
	respMsg, err := stub.InvokeRpc(ctx, methodDesc, reqMsg)
	if err != nil {
		return fmt.Errorf("RPC failed: %v", err)
	}

	// Use protojson to marshal the response, which works with the older proto.Message interface.
	marshler := jsonpb.Marshaler{}
	jsonStr, err := marshler.MarshalToString(respMsg)
	if err != nil {
		return fmt.Errorf("Failed to marshal response: %v", err)
	}

	var data interface{}

	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return fmt.Errorf("Failed to parse JSON: %w", err)
	}

	opaValue, err := ast.InterfaceToValue(data)
	if err != nil {
		return fmt.Errorf("Failed to parse data: %w", err)
	}

	// Return a string by invoking the given iterator function
	return iter(ast.NewTerm(opaValue))
}

func init() {
	RegisterBuiltinFunc(ast.GrpcCall.Name, builtinGrpcCall)
}
