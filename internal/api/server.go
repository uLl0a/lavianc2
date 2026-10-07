package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime/debug"
	"time"

	"github.com/google/uuid"
	adminv1 "github.com/uLl0a/lavianc2/gen/admin/v1"
	"github.com/uLl0a/lavianc2/internal/crypto"
	"github.com/uLl0a/lavianc2/internal/events"
	"github.com/uLl0a/lavianc2/internal/models"
	"github.com/uLl0a/lavianc2/internal/profiles"
	"github.com/uLl0a/lavianc2/internal/storage"
	"github.com/uLl0a/lavianc2/internal/tasks"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

// Server es el servidor gRPC de administración.
type Server struct {
	addr string
	log  *slog.Logger

	store       *storage.Store
	engine      *tasks.Engine
	bus         *events.Bus
	profiles    *profiles.Registry
	dnsProfiles *profiles.DNSRegistry
	serverKeys  *crypto.ServerKeyStore

	grpcServer *grpc.Server
}

// Config agrupa las dependencias del servidor gRPC.
type Config struct {
	Addr     string
	CertFile string
	KeyFile  string
	CAFile   string

	Store        *storage.Store
	Engine       *tasks.Engine
	Bus          *events.Bus
	Profiles     *profiles.Registry
	DNSProfiles  *profiles.DNSRegistry
	QUICProfiles *profiles.QUICRegistry
	ServerKeys   *crypto.ServerKeyStore

	RepoRoot string
}

// NewServer crea el servidor gRPC con mTLS.
func NewServer(cfg Config, log *slog.Logger) (*Server, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("api: cargar certificado: %w", err)
	}

	caPEM, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("api: leer CA: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("api: CA inválida")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
	}
	creds := credentials.NewTLS(tlsConfig)

	// Orden de interceptores (unary):
	//   1. recovery   → atrapa panics antes de que maten el server
	//   2. mTLS       → verifica que hay cert válido (no autoriza)
	//   3. operator   → busca operador en DB, rechaza si no existe/disabled,
	//                   inyecta ID y rol en el contexto
	//   4. authorize  → consulta el rol y compara con el mínimo por método
	unaryInterceptor := chainUnary(
		recoveryUnaryInterceptor(log),
		mTLSAuthInterceptor(),
		operatorContextInterceptor(cfg.Store),
		authorizeByRoleInterceptor(),
	)
	streamInterceptor := chainStream(
		recoveryStreamInterceptor(log),
		mTLSStreamAuthInterceptor(),
		operatorContextStreamInterceptor(cfg.Store),
		authorizeByRoleStreamInterceptor(),
	)

	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.UnaryInterceptor(unaryInterceptor),
		grpc.StreamInterceptor(streamInterceptor),
		grpc.MaxRecvMsgSize(50<<20),
		grpc.MaxSendMsgSize(50<<20),
	)

	adminSvc := NewAdminService(
		cfg.Store,
		cfg.Engine,
		cfg.Bus,
		cfg.Profiles,
		cfg.DNSProfiles,
		cfg.QUICProfiles,
		cfg.ServerKeys,
		cfg.RepoRoot,
		cfg.CAFile,
	)
	adminv1.RegisterAdminServiceServer(grpcServer, adminSvc)

	reflection.Register(grpcServer)

	return &Server{
		addr:        cfg.Addr,
		log:         log,
		store:       cfg.Store,
		engine:      cfg.Engine,
		bus:         cfg.Bus,
		profiles:    cfg.Profiles,
		dnsProfiles: cfg.DNSProfiles,
		serverKeys:  cfg.ServerKeys,
		grpcServer:  grpcServer,
	}, nil
}

// Start arranca el servidor gRPC.
func (s *Server) Start() error {
	lis, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("api: listen: %w", err)
	}
	s.log.Info("gRPC admin API escuchando", "addr", s.addr, "mtls", true)
	return s.grpcServer.Serve(lis)
}

// Stop apaga el servidor gracefulmente con timeout.
func (s *Server) Stop() {
	done := make(chan struct{})
	go func() {
		s.grpcServer.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
		s.log.Info("gRPC server detenido limpiamente")
	case <-time.After(10 * time.Second):
		s.log.Warn("gRPC server forzando parada")
		s.grpcServer.Stop()
	}
}

func recoveryUnaryInterceptor(log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Error("panic en handler gRPC",
					"method", info.FullMethod,
					"panic", r,
					"stack", string(debug.Stack()),
				)
				err = status.Errorf(codes.Internal, "panic interno: %v", r)
			}
		}()
		return handler(ctx, req)
	}
}

// recoveryStreamInterceptor atrapa panics en handlers stream.
func recoveryStreamInterceptor(log *slog.Logger) grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) (err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Error("panic en stream gRPC",
					"method", info.FullMethod,
					"panic", r,
					"stack", string(debug.Stack()),
				)
				err = status.Errorf(codes.Internal, "panic interno: %v", r)
			}
		}()
		return handler(srv, ss)
	}
}

func mTLSAuthInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if _, err := extractCN(ctx); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func mTLSStreamAuthInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if _, err := extractCN(ss.Context()); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

func operatorContextInterceptor(store *storage.Store) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		ctx, err := injectOperatorContext(ctx, store, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func operatorContextStreamInterceptor(store *storage.Store) grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx, err := injectOperatorContext(ss.Context(), store, info.FullMethod)
		if err != nil {
			return err
		}
		wrapped := &serverStreamWithContext{ServerStream: ss, ctx: ctx}
		return handler(srv, wrapped)
	}
}

func injectOperatorContext(
	ctx context.Context,
	store *storage.Store,
	method string,
) (context.Context, error) {
	cn, err := extractCN(ctx)
	if err != nil {
		return nil, err
	}

	op, err := store.Operators.GetByUsername(ctx, cn)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "buscar operador: %v", err)
	}
	if op == nil {
		return nil, status.Errorf(codes.Unauthenticated,
			"operador %q no registrado (CN del certificado sin fila en operators)", cn)
	}
	if op.Status != models.OperatorActive {
		return nil, status.Errorf(codes.PermissionDenied,
			"operador %q no está activo (status=%s)", cn, op.Status)
	}

	ctx = withOperatorID(ctx, op.ID)
	ctx = withOperatorRole(ctx, op.Role)
	return ctx, nil
}

type serverStreamWithContext struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *serverStreamWithContext) Context() context.Context {
	return s.ctx
}

// roleRank ordena los roles para comparar con >=.
var roleRank = map[string]int{
	"viewer":   1,
	"operator": 2,
	"admin":    3,
}

var methodRequirements = map[string]string{
	// Admin-only
	"/admin.v1.AdminService/CreateOperator": "admin",
	"/admin.v1.AdminService/ListOperators":  "admin",
	"/admin.v1.AdminService/CreateListener": "admin",

	// Operator-or-higher
	"/admin.v1.AdminService/KillImplant":  "operator",
	"/admin.v1.AdminService/BuildImplant": "operator",
	"/admin.v1.AdminService/SubmitTask":   "operator",

	// viewer-or-higher (implícito por default, se listan por claridad)
	"/admin.v1.AdminService/ListImplants":     "viewer",
	"/admin.v1.AdminService/GetImplant":       "viewer",
	"/admin.v1.AdminService/ListListeners":    "viewer",
	"/admin.v1.AdminService/ListHTTPProfiles": "viewer",
	"/admin.v1.AdminService/ListDNSProfiles":  "viewer",
	"/admin.v1.AdminService/ListQUICProfiles": "viewer",
	"/admin.v1.AdminService/StreamTaskEvents": "viewer",
	"/admin.v1.AdminService/StreamAudit":      "viewer",
}

// authorizeByRoleInterceptor compara el rol del contexto con el mínimo
// requerido por el método.
func authorizeByRoleInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if err := authorizeByRole(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func authorizeByRoleStreamInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if err := authorizeByRole(ss.Context(), info.FullMethod); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

func authorizeByRole(ctx context.Context, method string) error {
	role, ok := operatorRoleFromContext(ctx)
	if !ok {
		return status.Error(codes.Internal,
			"rol de operador no inyectado en el contexto (¿interceptor en orden incorrecto?)")
	}

	required, found := methodRequirements[method]
	if !found {
		// Default: cualquier operador autenticado.
		required = "viewer"
	}

	currentRank, ok := roleRank[role]
	if !ok {
		return status.Errorf(codes.PermissionDenied,
			"rol %q desconocido para %s", role, method)
	}
	requiredRank := roleRank[required]

	if currentRank < requiredRank {
		return status.Errorf(codes.PermissionDenied,
			"rol %q insuficiente para %s (requiere %q)",
			role, method, required)
	}
	return nil
}

// extractCN obtiene el Common Name del certificado mTLS del cliente.
func extractCN(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return "", status.Error(codes.Unauthenticated, "sin autenticación mTLS")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "auth info inválida")
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", status.Error(codes.Unauthenticated, "certificado no verificado")
	}
	return tlsInfo.State.VerifiedChains[0][0].Subject.CommonName, nil
}

func chainUnary(interceptors ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		chain := handler
		for i := len(interceptors) - 1; i >= 0; i-- {
			current := interceptors[i]
			next := chain
			chain = func(c context.Context, r any) (any, error) {
				return current(c, r, info, next)
			}
		}
		return chain(ctx, req)
	}
}

func chainStream(interceptors ...grpc.StreamServerInterceptor) grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		chain := handler
		for i := len(interceptors) - 1; i >= 0; i-- {
			current := interceptors[i]
			next := chain
			chain = func(s any, stream grpc.ServerStream) error {
				return current(s, stream, info, next)
			}
		}
		return chain(srv, ss)
	}
}

type ctxKey int

const (
	operatorIDKey ctxKey = iota
	operatorRoleKey
)

func withOperatorID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, operatorIDKey, id)
}

func withOperatorRole(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, operatorRoleKey, role)
}

func operatorIDFromContext(ctx context.Context) uuid.UUID {
	if v, ok := ctx.Value(operatorIDKey).(uuid.UUID); ok {
		return v
	}
	return uuid.Nil
}

func operatorRoleFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(operatorRoleKey).(string)
	return v, ok
}
