package main

import (
	"log"
	"net/http"
)

func main() {
	const port = "8080"
	const FilePathRoot = "."
	const ChirpyFilePath = "logo.png"

	mux := http.NewServeMux()
	go mux.Handle("/", http.FileServer(http.Dir(FilePathRoot)))
	go mux.Handle("/assets", http.FileServer(http.Dir(ChirpyFilePath)))
	corsMux := middlewareCors(mux)
	srv := &http.Server{
		Handler: corsMux,
		Addr:    ":" + port,
	}
	log.Printf("Serving files from %s on port %s", FilePathRoot, port)
	log.Fatal(srv.ListenAndServe())
}

func middlewareCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
