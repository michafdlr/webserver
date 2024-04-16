package main

import (
	"log"
	"net/http"
)

func main() {
	const port = "8080"
	const FilePathRoot = "."
	//const ChirpyFilePath = "logo.png"

	mux := http.NewServeMux()
	go mux.Handle("/app/*", http.StripPrefix("/app", http.FileServer(http.Dir(FilePathRoot))))
	go mux.HandleFunc("/healthz", HealthzHandler)
	//go mux.HandleFunc("/app/*", AppHandler)
	//go mux.Handle("/assets", http.FileServer(http.Dir(ChirpyFilePath)))
	corsMux := middlewareCors(mux)
	srv := &http.Server{
		Handler: corsMux,
		Addr:    ":" + port,
	}
	log.Printf("Serving files from %s on port %s", FilePathRoot, port)
	log.Fatal(srv.ListenAndServe())
}

func HealthzHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

// func AppHandler(w http.ResponseWriter, req *http.Request) {
// 	w.Header().Set("Content-Type", "text/html; charset=utf-8")
// 	w.WriteHeader(200)
// 	w.Write([]byte("OK"))
// }

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
