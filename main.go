package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/michafdlr/webserver/internal/database"
)

func main() {
	godotenv.Load()
	const port = "8080"
	const FilePathRoot = "."
	db, err := database.NewDB("database.json")
	if err != nil {
		log.Fatalf("Error creating database: %v", err)
	}
	jwtSecret := os.Getenv("JWT_SECRET")
	apikey := os.Getenv("API_KEY")

	apiCfg := apiConfig{
		fileserverHits: 0,
		DB:             db,
		JwtSecret:      jwtSecret,
		ApiKey:         apikey,
	}

	mux := http.NewServeMux()
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(FilePathRoot)))))
	mux.HandleFunc("GET /api/healthz", HealthzHandler)
	mux.HandleFunc("GET /admin/metrics", apiCfg.CountHandler)
	mux.HandleFunc("/api/reset", apiCfg.ResetHandler)
	mux.HandleFunc("POST /api/chirps", apiCfg.PostChirpHandler)
	mux.HandleFunc("GET /api/chirps", apiCfg.GetChirpHandler)
	mux.HandleFunc("GET /api/chirps/{id}", apiCfg.SingleChirpGetHandler)
	mux.HandleFunc("DELETE /api/chirps/{id}", apiCfg.DeleteChirpHandler)
	mux.HandleFunc("POST /api/users", apiCfg.PostUsersHandler)
	mux.HandleFunc("PUT /api/users", apiCfg.PutUsersHandler)
	mux.HandleFunc("POST /api/login", apiCfg.ValidateUsersHandler)
	mux.HandleFunc("POST /api/revoke", apiCfg.RevokeHandler)
	mux.HandleFunc("POST /api/refresh", apiCfg.RefreshHandler)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.UpgradeHandler)
	corsMux := middlewareCors(mux)
	srv := &http.Server{
		Handler: corsMux,
		Addr:    ":" + port,
	}
	log.Printf("Serving files from %s on port %s", FilePathRoot, port)
	log.Fatal(srv.ListenAndServe())
}

type apiConfig struct {
	fileserverHits int
	DB             *database.DB
	JwtSecret      string
	ApiKey         string
}

type Chirp struct {
	Body     string `json:"body"`
	ID       int    `json:"id"`
	AuthorID int    `json:"author_id"`
}

type User struct {
	Email        string `json:"email"`
	ID           int    `json:"id"`
	Password     string `json:"password"`
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	IsChirpyRed  bool   `json:"is_chirpy_red"`
}

type RefreshToken struct {
	//ID      string `json:"id"`
	Revoked bool `json:"revoked"`
}

type UserDisplay struct {
	Email string `json:"email"`
	ID    int    `json:"id"`
}

type UserTokenDisplay struct {
	//Email string `json:"email"`
	//ID    int    `json:"id"`
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}
