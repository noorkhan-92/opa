package topdown

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang/protobuf/jsonpb"
	"github.com/jhump/protoreflect/dynamic"
	"github.com/jhump/protoreflect/dynamic/grpcdynamic"
	"github.com/jhump/protoreflect/grpcreflect"
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

func getToken() string {
	config := &clientcredentials.Config{
		ClientID:     "018ef626-ce6f-7388-aed0-b3e2914c6170",
		ClientSecret: "BwBb3zhjsLbIaTkD03YuBqiXjOOKtM3D",
		TokenURL:     "https://idp.dbank.engineering/realms/internal-services/protocol/openid-connect/token",
		Scopes:       []string{},
	}

	token, err := config.Token(context.Background())
	if err != nil {
		fmt.Errorf("Failed to get token from keycloak: %v", err)
	}

	return string(token.AccessToken)
}

// custom builtin function for calling grpc service, implements topdown.BuiltinFunc
func builtinGrpcCall(_ BuiltinContext, args []*ast.Term, iter func(*ast.Term) error) error {
	// Get the first argument as a string, returning an error if it's not the correct type.
	serverUrl, _ := builtins.StringOperand(args[0].Value, 1)
	serviceName, _ := builtins.StringOperand(args[1].Value, 2)
	methodName, _ := builtins.StringOperand(args[2].Value, 3)
	request, _ := builtins.ObjectOperand(args[3].Value, 4)

	// grpc reflection
	// connect to the grpc server
	env := os.Getenv("OPA_ID")
	fmt.Println("os user" + env)
	token := getToken()
	conn, err := grpc.NewClient(string(serverUrl), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithUnaryInterceptor(authInterceptor(token)))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Create a reflection client to dynamically fetch service descriptors.
	refClient := grpcreflect.NewClientV1(context.Background(), grpc_reflection_v1.NewServerReflectionClient(conn))
	defer refClient.Reset()

	// Resolve the service descriptor dynamically.
	serviceDesc, err := refClient.ResolveService(string(serviceName))
	if err != nil {
		log.Fatalf("Failed to resolve service %q: %v", serviceName, err)
	}

	// Find the method descriptor by name.
	methodDesc := serviceDesc.FindMethodByName(string(methodName))
	if methodDesc == nil {
		log.Fatalf("Method %q not found in service %q", methodName, serviceName)
	}

	// Create a dynamic stub for making RPC calls.
	stub := grpcdynamic.NewStub(conn)

	// Create a dynamic message for the request.
	reqMsg := dynamic.NewMessage(methodDesc.GetInputType())
	// Set fields on the request. In this example, we set a field "name".
	var jsonMap map[string]interface{}
	if err := ast.As(request, &jsonMap); err != nil {
		log.Fatalf("The request %q is not a valid json: %v", request.String(), err)
	}

	for key, value := range jsonMap {
		if err := reqMsg.TrySetFieldByName(key, value); err != nil {
			log.Fatalf("Failed to set field: %v", err)
		}
	}

	// Prepare context with a timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Invoke the RPC dynamically using the method descriptor.
	respMsg, err := stub.InvokeRpc(ctx, methodDesc, reqMsg)
	if err != nil {
		log.Fatalf("RPC failed: %v", err)
	}

	// Use protojson to marshal the response, which works with the older proto.Message interface.
	marshler := jsonpb.Marshaler{}
	jsonStr, err := marshler.MarshalToString(respMsg)
	if err != nil {
		log.Fatalf("Failed to marshal response: %v", err)
	}

	var data interface{}

	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	opaValue, _ := ast.InterfaceToValue(data)

	// Return a string by invoking the given iterator function
	return iter(ast.NewTerm(opaValue))
}

func init() {
	RegisterBuiltinFunc(ast.GrpcCall.Name, builtinGrpcCall)
}
