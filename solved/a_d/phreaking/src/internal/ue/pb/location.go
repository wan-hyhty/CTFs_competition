package pb

import (
	"os"

	"go.uber.org/zap"
	"golang.org/x/net/context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	status "google.golang.org/grpc/status"
)

type Server struct {
	UnimplementedLocationServer
}

func (s *Server) UpdateLocation(ctx context.Context, loc *Loc) (*Response, error) {
	logger := zap.Must(zap.NewDevelopment())
	defer logger.Sync()
	log := logger.Sugar()
	log.Infof("GPS location update: %s", loc.Position)
	file, err := os.OpenFile("/service/data/location.data", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Error(err)
	}
	defer file.Close()
	if _, err := file.WriteString(loc.Position + "\n"); err != nil {
		log.Fatal(err)
	}

	return &Response{}, nil
}

// auth middleware for each rpc request
func AuthInterceptor(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	meta, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "INTERNAL_SERVER_ERROR")
	}
	if len(meta["auth"]) != 1 {
		return nil, status.Error(codes.Unauthenticated, "INTERNAL_SERVER_ERROR")
	}
	if meta.Get("auth")[0] != string(os.Getenv("PHREAKING_GRPC_PASS")) {
		return nil, status.Error(codes.Unauthenticated, "WRONG SECRET")
	}

	return handler(ctx, req) // go to function.
}
