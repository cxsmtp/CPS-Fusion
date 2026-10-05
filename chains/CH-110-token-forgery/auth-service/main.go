// Nexa Commerce - auth service.
//
// CHAIN CH-110 lives in this file plus public/js/checkout.js.
//
// FIX (scan cc434dd7): the previous revision called server.ListenAndServe(),
// which Checkmarx flags as Plain_Text_Transport_Layer_in_Server at HIGH. The
// listener is now TLS. Every finding in this specimen must stay at Medium or
// below, so the transport itself has to be sound.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const listenAddr = "0.0.0.0:8082"

// CH-110 F1 - Use_of_Hardcoded_Password (expect: Medium)
//
// The service account passphrase used to derive the token signing key is
// compiled into the binary and compared directly against caller-supplied
// input, so anyone with the artefact holds the key material. It is also the
// value the client-side digest in public/js/checkout.js reproduces.
var serviceAccountPassword = "nexa-auth-service-passphrase-2026"

func authenticateService(suppliedPassword string) bool {
	return suppliedPassword == serviceAccountPassword
}

func signingKey() []byte {
	return []byte(serviceAccountPassword)
}

// parseJWTClaims parses a bearer token.
//
// CH-110 F3 - JWT_No_Claims_Directives_Validation (expect: Low)
//
// The parser is constructed with no claims directives: no expiry check, no
// issuer check, no audience check, and no algorithm allow-list beyond the
// default. Combined with the hardcoded key above and the reproducible
// client-side digest, a forged token with attacker-chosen claims is accepted
// for as long as the caller cares to use it.
func parseJWTClaims(tokenString string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	parser := jwt.NewParser()
	_, err := parser.ParseWithClaims(tokenString, claims,
		func(token *jwt.Token) (interface{}, error) {
			return signingKey(), nil
		})
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func handleIntrospect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if !authenticateService(r.Header.Get("X-Service-Password")) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"active":false,"error":"service auth failed"}`))
		return
	}

	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"active":false}`))
		return
	}

	claims, err := parseJWTClaims(token)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"active":false,"error":"unreadable token"}`))
		return
	}

	out, _ := json.Marshal(map[string]any{
		"active": true,
		"sub":    claims["sub"],
		"role":   claims["role"],
		"iss":    claims["iss"],
	})
	_, _ = w.Write(out)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write([]byte(`{"status":"ok","service":"auth"}`))
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/introspect", handleIntrospect)
	mux.HandleFunc("/healthz", handleHealth)
	mux.Handle("/js/", http.StripPrefix("/js/", http.FileServer(http.Dir("public/js"))))

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	certFile := os.Getenv("NEXA_TLS_CERT")
	keyFile := os.Getenv("NEXA_TLS_KEY")
	if certFile == "" {
		certFile = "certs/server.crt"
	}
	if keyFile == "" {
		keyFile = "certs/server.key"
	}

	log.Printf("[auth] listening on %s over TLS", listenAddr)
	if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
		log.Fatalf("[auth] server stopped: %v", err)
	}
}
