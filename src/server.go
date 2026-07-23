package src

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nsmithuk/local-kms/src/config"
	"github.com/nsmithuk/local-kms/src/data"
	"github.com/nsmithuk/local-kms/src/handler"
)

func Run(ctx context.Context, port, seedPath string) {

	//-----------
	// DB Setup

	database := data.NewDatabase(ctx, config.DatabasePath)
	defer func() {
		if err := database.Close(); err != nil {
			logger.ErrorContext(ctx, "Failed to close database", "error", err)
		}
	}()

	//-----------
	// Health Check

	healthReport := database.HealthCheck()
	if healthReport.DiskSpaceIssue != "" {
		logger.WarnContext(ctx, "Low disk space", "issue", healthReport.DiskSpaceIssue)
	}
	if len(healthReport.Entries) > 0 {
		logger.WarnContext(ctx, "Database corruption detected",
			"corruptedKeys", healthReport.CorruptedKeys,
			"corruptedAliases", healthReport.CorruptedAliases,
			"corruptedTags", healthReport.CorruptedTags,
		)
		for _, entry := range healthReport.Entries {
			logger.WarnContext(ctx, "Corruption entry", "description", entry.Description)
		}
		logger.WarnContext(ctx, "Run recovery tool", "command", "make build-recovery && ./recovery -db "+config.DatabasePath)
	}

	//-----------
	// Seeding

	seed(ctx, seedPath, database)

	//-----------
	// Start

	http.HandleFunc("/_health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, "OK")
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		HandleRequest(w, r, database)
	})

	logger.InfoContext(ctx, "Data storage path", "path", config.DatabasePath)

	addr := ":" + port

	// Bind the listener explicitly, immediately before serving, so port-binding
	// failures surface before we log "started", and so PORT=0 (useful in CI)
	// resolves to the real port. Binding any earlier would leave the socket
	// accepting connections into the kernel backlog while DB setup/seeding are
	// still running, causing clients to hang instead of getting a fast refusal.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to bind", "addr", addr, "error", err)
		os.Exit(1)
	}

	parts := strings.Split(ln.Addr().String(), ":")
	resolvedPort := parts[len(parts)-1]
	logger.InfoContext(ctx, "Local KMS started", "addr", "0.0.0.0:"+resolvedPort)

	srv := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := srv.Serve(ln); err != nil {
		logger.ErrorContext(ctx, "Server failed", "error", err)
		os.Exit(1)
	}

}

func HandleRequest(w http.ResponseWriter, r *http.Request, database *data.Database) {
	requestId, err := uuid.NewRandom()
	if err != nil {
		logger.WarnContext(r.Context(), "Failed to generate request id", "error", err)
	}
	target := strings.Split(r.Header.Get("X-Amz-Target"), ".")
	operation := ""
	if len(target) >= 2 {
		operation = target[1]
	}
	ctx := withRequestMeta(r.Context(), requestId.String(), operation, r.RemoteAddr)

	logger.DebugContext(ctx, "request", "method", r.Method, "url", r.URL.String())

	if r.URL.Path != "/" {
		error404(w)

	} else if r.Method != "POST" {
		error405(w)

	} else if !strings.Contains(r.Header.Get("Content-Type"), "json") {
		// Allows both application/x-amz-json-1.1 and application/json
		error415(w)

	} else {

		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.Header().Set("x-amzn-requestid", requestId.String())

		h := handler.NewRequestHandler(r.WithContext(ctx), logger, database)

		if len(target) >= 2 {

			method := reflect.ValueOf(h).MethodByName(target[1])

			if method.IsValid() {

				result := method.Call([]reflect.Value{})

				if len(result) == 0 {
					logger.ErrorContext(ctx, "Missing expected response from reflected method call")
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}

				response, ok := result[0].Interface().(handler.Response)

				if !ok {
					logger.ErrorContext(ctx, "Unable to assert type of returned response")
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}

				respond(ctx, w, response)
				return
			}

		}

		// If we couldn't find a valid method matching the request
		logger.WarnContext(ctx, "unimplemented operation", "target", r.Header.Get("X-Amz-Target"))
		w.WriteHeader(501)
		// #nosec G705 -- local mock; response is plain text, not HTML.
		_, _ = fmt.Fprintf(w, "Passed X-Amz-Target (%s) is not implemented", r.Header.Get("X-Amz-Target"))
		return
	}

}

func respond(ctx context.Context, w http.ResponseWriter, r handler.Response) {
	logger.DebugContext(ctx, "response", "status", r.Code)
	w.WriteHeader(r.Code)
	// #nosec G705 -- local mock; response is JSON/plain text, not HTML.
	_, _ = fmt.Fprint(w, r.Body)
}

func error404(w http.ResponseWriter) {
	w.WriteHeader(404)
	_, _ = fmt.Fprint(w, "Page not found")
}

func error405(w http.ResponseWriter) {
	w.WriteHeader(405)
	_, _ = fmt.Fprint(w, "Method Not Allowed")
}

func error415(w http.ResponseWriter) {
	w.WriteHeader(415)
	_, _ = fmt.Fprint(w, "Only JSON based content types accepted")
}
