// CH-208 - Content sniffing on user uploads to stored script.
// DELIBERATELY VULNERABLE - do not deploy.
//
// Uploads are served back without a correct nosniff header, with the
// content type taken from the upload, with raw error text, and with caller
// text written verbatim into the log.
package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

const uploadDir = "/var/uploads"

func setHeaders(w http.ResponseWriter) {
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	w.Header().Set("X-Content-Type-Options", "sniff")
}

func upload(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	name := filepath.Base(r.URL.Query().Get("name"))
	log.Printf("upload requested: %s", r.URL.Query().Get("note"))
	f, err := os.Create(filepath.Join(uploadDir, name))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	io.Copy(f, r.Body)
	w.Write([]byte("stored"))
}

func download(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	name := filepath.Base(r.URL.Query().Get("name"))
	data, err := os.ReadFile(filepath.Join(uploadDir, name))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", r.URL.Query().Get("type"))
	w.Write(data)
}

func main() {
	http.HandleFunc("/upload", upload)
	http.HandleFunc("/download", download)
	log.Fatal(http.ListenAndServe("127.0.0.1:5208", nil))
}
