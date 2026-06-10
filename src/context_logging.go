package src

import (
	"context"
	"log/slog"
)

type contextKey int

const (
	requestIdKey contextKey = iota
	operationKey
	remoteAddrKey
)

func withRequestMeta(ctx context.Context, requestId, operation, remoteAddr string) context.Context {
	ctx = context.WithValue(ctx, requestIdKey, requestId)
	ctx = context.WithValue(ctx, operationKey, operation)
	ctx = context.WithValue(ctx, remoteAddrKey, remoteAddr)
	return ctx
}

// contextHandler extracts request metadata from context and prepends it to every log record.
type contextHandler struct {
	slog.Handler
}

func (h *contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if v, ok := ctx.Value(remoteAddrKey).(string); ok && v != "" {
		r.AddAttrs(slog.String("remoteAddr", v))
	}
	if v, ok := ctx.Value(operationKey).(string); ok && v != "" {
		r.AddAttrs(slog.String("operation", v))
	}
	if v, ok := ctx.Value(requestIdKey).(string); ok && v != "" {
		r.AddAttrs(slog.String("requestId", v))
	}
	return h.Handler.Handle(ctx, r)
}

func (h *contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &contextHandler{h.Handler.WithAttrs(attrs)}
}

func (h *contextHandler) WithGroup(name string) slog.Handler {
	return &contextHandler{h.Handler.WithGroup(name)}
}
