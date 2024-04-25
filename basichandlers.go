package main

import (
	"fmt"
	"log"
	"net/http"
)

func (apiCfg *apiConfig) CountHandler(w http.ResponseWriter, req *http.Request) {
	var adminHtml = `<html>

	<body>
			<h1>Welcome, Chirpy Admin</h1>
			<p>Chirpy has been visited %d times!</p>
	</body>

	</html>
	`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)
	log.Println("CountHandler called")
	//hits := fmt.Sprintf(adminHtml, apiCfg.fileserverHits)
	//fmt.Fprintf(w, adminHtml, apiCfg.fileserverHits)
	w.Write([]byte(fmt.Sprintf(adminHtml, apiCfg.fileserverHits)))
}

func (apiCfg *apiConfig) ResetHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	apiCfg.fileserverHits = 0
	hits := "Reset hits " + fmt.Sprintf("%d", apiCfg.fileserverHits)
	w.Write([]byte(hits))
}

func HealthzHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}
