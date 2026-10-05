// CH-208 - Upload store to content-sniffed script.
// DELIBERATELY VULNERABLE - do not deploy.
//
// Uploads are written world-readable into the directory the static file
// server publishes, the nosniff header is misconfigured, write errors are
// ignored, caller text is logged verbatim, and nothing stops the page being
// framed.
package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

const uploadDir = "/var/www/static/uploads"

func setHeaders(w http.ResponseWriter) {
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	w.Header().Set("X-Content-Type-Options", "sniff")
}

func upload(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	name := filepath.Base(r.URL.Query().Get("name"))
	log.Printf("upload requested: %s", r.URL.Query().Get("note"))
	f, err := os.OpenFile(filepath.Join(uploadDir, name), os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		http.Error(w, "upload failed", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	io.Copy(f, r.Body)
	w.Write([]byte("stored"))
}

func main() {
	http.HandleFunc("/upload", upload)
	log.Fatal(http.ListenAndServeTLS("127.0.0.1:5208", "server.crt", "server.key", nil))
}
