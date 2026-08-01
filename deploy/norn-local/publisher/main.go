package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/chain-lab/go-norn/rpc/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

func main() {
	if len(os.Args) != 5 {
		fail("usage: norn-local-publisher <target> <receiver> <key> <value-file>")
	}
	value, err := os.ReadFile(os.Args[4])
	if err != nil {
		fail(err.Error())
	}
	option, err := transportOption()
	if err != nil {
		fail(err.Error())
	}
	connection, err := grpc.Dial(os.Args[1], option)
	if err != nil {
		fail(err.Error())
	}
	defer connection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	response, err := pb.NewBlockchainClient(connection).SendTransactionWithData(
		ctx,
		&pb.SendTransactionWithDataReq{
			Type:     proto.String("set"),
			Receiver: proto.String(os.Args[2]),
			Key:      proto.String(os.Args[3]),
			Value:    proto.String(string(value)),
		},
	)
	if err != nil {
		fail(err.Error())
	}
	fmt.Printf("{\"transaction_hash\":\"%s\"}\n", response.GetTxHash())
}

func transportOption() (grpc.DialOption, error) {
	caFile := os.Getenv("NORN_PUBLISHER_TLS_CA_FILE")
	certFile := os.Getenv("NORN_PUBLISHER_TLS_CLIENT_CERT_FILE")
	keyFile := os.Getenv("NORN_PUBLISHER_TLS_CLIENT_KEY_FILE")
	if caFile == "" && certFile == "" && keyFile == "" {
		return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
	}
	if caFile == "" || certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("publisher TLS files must be configured together")
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("publisher CA file contains no certificates")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      pool,
		Certificates: []tls.Certificate{certificate},
		ServerName:   "localhost",
	})), nil
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
