package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
)

func TestWithRequestContextSetsID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	baseLogger := zerolog.Nop()
	r := gin.New()
	r.Use(withRequestContext(baseLogger))
	r.GET("/ping", func(c *gin.Context) {
		if requestID(c) == "" {
			t.Error("request ID not set")
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	if resp.Header().Get(requestIDHeader) == "" {
		t.Fatal("expected request ID header")
	}
	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.Code)
	}
}

func TestRespondErrorIncludesRequestID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	baseLogger := zerolog.Nop()
	r := gin.New()
	r.Use(withRequestContext(baseLogger))
	r.GET("/fail", func(c *gin.Context) {
		respondError(c, http.StatusBadRequest, "boom", baseLogger)
	})

	req := httptest.NewRequest(http.MethodGet, "/fail", nil)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: %d", resp.Code)
	}
	if resp.Header().Get(requestIDHeader) == "" {
		t.Fatal("missing request ID header")
	}
}
