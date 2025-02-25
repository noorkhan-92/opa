package topdown

import (
	"fmt"
	"os/exec"

	"log"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
)

// custom builtin function for calling grpc service, implements topdown.BuiltinFunc
func builtinGrpcCall(_ BuiltinContext, args []*ast.Term, iter func(*ast.Term) error) error {
	// Get the first argument as a string, returning an error if it's not the correct type.
	service_url, _ := builtins.StringOperand(args[1].Value, 2)
	request, _ := builtins.StringOperand(args[0].Value, 1)
	method_name, err := builtins.StringOperand(args[2].Value, 3)
	if err != nil {
		return err
	}

	fmt.Println(request.String())
	fmt.Println(service_url.String())
	fmt.Println(method_name.String())

	cmd := exec.Command("grpcurl", "-plaintext", "-d", string(request), string(service_url), string(method_name))
	output, error := cmd.Output()

	if error != nil {
		fmt.Println(error.Error())
		stdError := error.(*exec.ExitError).Stderr
		fmt.Println(string(stdError))
		return error
	}
	if err != nil {
		log.Fatalf("Failed to call SayHello: %v", err)
	}

	// Return a string by invoking the given iterator function
	return iter(ast.StringTerm(string(string(output) + string(request) + " calling grpc service.")))
}

func init() {
	RegisterBuiltinFunc(ast.GrpcCall.Name, builtinGrpcCall)
}
