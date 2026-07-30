package server_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/sendrec/sendrec/internal/capture"
	"github.com/sendrec/sendrec/internal/server"
)

const testCaptureSecret = "test-capture-secret"

func newServerWithCapture(t *testing.T, captureSecret string) (*server.Server, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create pgxmock pool: %v", err)
	}
	t.Cleanup(func() { mock.Close() })

	srv := server.New(server.Config{
		DB:                 mock,
		Pinger:             &mockPinger{err: nil},
		Storage:            &mockStorage{},
		JWTSecret:          "test-secret",
		BaseURL:            "https://localhost:8080",
		S3PublicEndpoint:   "https://storage.example.com",
		CaptureTokenSecret: captureSecret,
	})
	return srv, mock
}

// A stock deployment has no parent application to trust, so the hand-off route
// must not merely refuse — it must not exist.
func TestCaptureRouteAbsentWithoutASecret(t *testing.T) {
	srv, _ := newServerWithCapture(t, "")

	rec := executeRequest(srv, http.MethodGet, "/capture?token=anything")

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 with no CAPTURE_TOKEN_SECRET configured, got %d", rec.Code)
	}
}

func TestCaptureRouteRegisteredWithASecret(t *testing.T) {
	srv, mock := newServerWithCapture(t, testCaptureSecret)

	token, err := capture.Mint(testCaptureSecret, &capture.Claims{
		UserID:     "parent-user-1",
		CustomerID: "parent-customer-1",
		Email:      "alice@example.com",
		Name:       "Alice",
		ExpiresAt:  time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	mock.ExpectQuery(`SELECT user_id FROM external_identities`).
		WithArgs(capture.Provider, "parent-user-1").
		WillReturnRows(pgxmock.NewRows([]string{"user_id"}).AddRow("local-user-1"))
	mock.ExpectExec(`INSERT INTO refresh_tokens`).
		WithArgs(pgxmock.AnyArg(), "local-user-1", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	req := httptest.NewRequest(http.MethodGet, "/capture?token="+token, nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 from the capture route, got %d: %s", rec.Code, rec.Body.String())
	}
	if location := rec.Header().Get("Location"); location != "/" {
		t.Errorf("expected a redirect to the recorder at /, got %q", location)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet database expectations: %v", err)
	}
}

// The SPA fallback serves index.html for unknown paths. /capture must be
// matched by the router BEFORE that fallback, or the hand-off silently renders
// the login screen instead of establishing anything.
func TestCaptureRouteIsNotSwallowedByTheSPAFallback(t *testing.T) {
	srv, _ := newServerWithCapture(t, testCaptureSecret)

	// A token this route will refuse — the point is which handler refuses it.
	rec := executeRequest(srv, http.MethodGet, "/capture?token=not-a-real-token")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected the capture handler to answer with 401, got %d — the SPA fallback took the route", rec.Code)
	}
}
