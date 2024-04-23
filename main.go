package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/michafdlr/webserver/internal/database"
	"golang.org/x/crypto/bcrypt"
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

	apiCfg := apiConfig{
		fileserverHits: 0,
		DB:             db,
		JwtSecret:      jwtSecret,
	}

	mux := http.NewServeMux()
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(FilePathRoot)))))
	mux.HandleFunc("GET /api/healthz", HealthzHandler)
	mux.HandleFunc("GET /admin/metrics", apiCfg.CountHandler)
	mux.HandleFunc("/api/reset", apiCfg.ResetHandler)
	mux.HandleFunc("POST /api/chirps", apiCfg.PostChirpHandler)
	mux.HandleFunc("GET /api/chirps", apiCfg.GetChirpHandler)
	mux.HandleFunc("GET /api/chirps/{id}", apiCfg.SingleChirpGetHandler)
	mux.HandleFunc("POST /api/users", apiCfg.PostUsersHandler)
	mux.HandleFunc("PUT /api/users", apiCfg.PutUsersHandler)
	mux.HandleFunc("POST /api/login", apiCfg.ValidateUsersHandler)
	mux.HandleFunc("POST /api/revoke", apiCfg.RevokeHandler)
	mux.HandleFunc("POST /api/refresh", apiCfg.RefreshHandler)

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

func HealthzHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

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

func respondWithError(w http.ResponseWriter, code int, msg string) {
	if code > 499 {
		log.Printf("Responding with 5XX error: %s", msg)
	}
	type errorResponse struct {
		Error string `json:"error"`
	}
	respondWithJSON(w, code, errorResponse{
		Error: msg,
	})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	dat, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(code)
	w.Write(dat)
}

func validateChirp(body string) (string, error) {
	const maxChirpLength = 140
	if len(body) > maxChirpLength {
		return "", errors.New("Chirp is too long")
	}

	badWords := map[string]struct{}{
		"kerfuffle": {},
		"sharbert":  {},
		"fornax":    {},
	}
	cleaned := getCleanedBody(body, badWords)
	return cleaned, nil
}

func getCleanedBody(body string, badWords map[string]struct{}) string {
	words := strings.Split(body, " ")
	for i, word := range words {
		loweredWord := strings.ToLower(word)
		if _, ok := badWords[loweredWord]; ok {
			words[i] = "****"
		}
	}
	cleaned := strings.Join(words, " ")
	return cleaned
}

func (apiCfg *apiConfig) PostChirpHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters")
		return
	}

	cleaned, err := validateChirp(params.Body)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	chirp, err := apiCfg.DB.CreateChirp(cleaned, apiCfg.JwtSecret, r.Header)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't create chirp")
		return
	}

	respondWithJSON(w, http.StatusCreated, Chirp{
		ID:       chirp.ID,
		Body:     chirp.Body,
		AuthorID: chirp.AuthorID,
	})
}

func (apiCfg *apiConfig) GetChirpHandler(w http.ResponseWriter, r *http.Request) {
	dbChirps, err := apiCfg.DB.GetChirps()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't retrieve chirps")
		return
	}

	chirps := []Chirp{}
	for _, dbChirp := range dbChirps {
		chirps = append(chirps, Chirp{
			ID:       dbChirp.ID,
			Body:     dbChirp.Body,
			AuthorID: dbChirp.AuthorID,
		})
	}

	sort.Slice(chirps, func(i, j int) bool {
		return chirps[i].ID < chirps[j].ID
	})

	respondWithJSON(w, http.StatusOK, chirps)
}

func (apiCfg *apiConfig) SingleChirpGetHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid ID")
		return
	}
	dbChirps, err := apiCfg.DB.GetChirps()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't retrieve chirps")
		return
	}
	if id < 1 || id > len(dbChirps) {
		respondWithError(w, http.StatusNotFound, "Chirp not found")
		return
	}
	chirp := dbChirps[id-1]
	respondWithJSON(w, http.StatusOK, Chirp{ID: chirp.ID, Body: chirp.Body, AuthorID: chirp.AuthorID})
}

func (apiCfg *apiConfig) PostUsersHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters")
		return
	}
	user, err := apiCfg.DB.CreateUser(params.Email, params.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't create user")
		return
	}

	respondWithJSON(w, http.StatusCreated, UserDisplay{
		Email: user.Email,
		ID:    user.ID,
	})
}

func (apiCfg *apiConfig) PutUsersHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	tokenString, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	log.Printf("Token:%s", tokenString)
	if !found {
		respondWithError(w, http.StatusInternalServerError, "Couldn't get token")
		return
	}
	claimsStruct := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claimsStruct, func(token *jwt.Token) (interface{}, error) {
		return []byte(apiCfg.JwtSecret), nil
	})
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Token is invalid")
		return
	}
	issuer, err := token.Claims.GetIssuer()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't get issuer")
		return
	}
	if issuer == "chirpy-refresh" {
		respondWithError(w, http.StatusUnauthorized, "Got Refresh-token")
		return
	}
	userID, err := token.Claims.GetSubject()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't get user ID")
		return
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters")
		return
	}
	userIDInt, err := strconv.Atoi(userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't convert user ID")
		return
	}
	user, err := apiCfg.DB.UpdateUser(userIDInt, params.Email, params.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't update user")
		return
	}

	respondWithJSON(w, http.StatusOK, UserDisplay{
		Email: user.Email,
		ID:    user.ID,
	})
}

func (apiCfg *apiConfig) ValidateUsersHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		//Expires  int    `json:"expires_in_seconds"`
	}
	type response struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters")
		return
	}
	user, err := apiCfg.DB.GetUserByEmail(params.Email)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't find user")
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(params.Password))
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Wrong password")
		return
	}

	AccessClaims := jwt.RegisteredClaims{
		Issuer:    "chirpy-access",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Hour * 1)),
		Subject:   fmt.Sprintf("%d", user.ID),
	}
	RefreshClaims := jwt.RegisteredClaims{
		Issuer:    "chirpy-refresh",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Hour * 24 * 60)),
		Subject:   fmt.Sprintf("%d", user.ID),
	}
	accesstoken := jwt.NewWithClaims(jwt.SigningMethodHS256, AccessClaims)
	signedAccessToken, err := accesstoken.SignedString([]byte(apiCfg.JwtSecret))
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't sign secret")
		return
	}

	refreshtoken := jwt.NewWithClaims(jwt.SigningMethodHS256, RefreshClaims)
	signedRefreshToken, err := refreshtoken.SignedString([]byte(apiCfg.JwtSecret))
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't sign secret")
		return
	}
	userID := user.ID
	err = apiCfg.DB.UpdateUserToken(userID, signedAccessToken, "access")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't update access token")
	}
	err = apiCfg.DB.UpdateUserToken(userID, signedAccessToken, "refresh")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't update refresh token")
	}
	_, err = apiCfg.DB.CreateRefreshToken(signedRefreshToken)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Couldn't create refresh token in DB")
		return
	}

	respondWithJSON(w, http.StatusOK, response{
		Token:        signedAccessToken,
		RefreshToken: signedRefreshToken,
	})
}

func (apiCfg *apiConfig) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	tokenString, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	log.Printf("Token:%s", tokenString)
	if !found {
		respondWithError(w, http.StatusInternalServerError, "Couldn't get token")
		return
	}
	claimsStruct := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claimsStruct, func(token *jwt.Token) (interface{}, error) {
		return []byte(apiCfg.JwtSecret), nil
	})
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Token is invalid")
		return
	}
	issuer, err := token.Claims.GetIssuer()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't get issuer")
		return
	}
	if issuer == "chirpy-access" {
		respondWithError(w, http.StatusUnauthorized, "Got Access-token")
		return
	}

	userID, err := token.Claims.GetSubject()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't get user ID")
		return
	}
	userIDInt, err := strconv.Atoi(userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't transform userid to int")
		return
	}
	// user, err := apiCfg.DB.GetUserByID(userIDInt)
	// if err != nil {
	// 	respondWithError(w, http.StatusInternalServerError, "Couldn't retrieve user")
	// 	return
	// }

	revoked, err := apiCfg.DB.CheckRevokedToken(tokenString)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't check if token was revoked")
		return
	}
	if revoked {
		respondWithError(w, http.StatusUnauthorized, "Refresh token was revoked")
		return
	}

	AccessClaims := jwt.RegisteredClaims{
		Issuer:    "chirpy-access",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Hour * time.Duration(1))),
		Subject:   fmt.Sprintf("%d", userIDInt),
	}
	accesstoken := jwt.NewWithClaims(jwt.SigningMethodHS256, AccessClaims)
	signedAccessToken, err := accesstoken.SignedString([]byte(apiCfg.JwtSecret))
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't sign secret")
		return
	}

	err = apiCfg.DB.UpdateUserToken(userIDInt, signedAccessToken, "access")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't update access token")
		return
	}
	type response struct {
		Token string `json:"token"`
	}
	respondWithJSON(w, http.StatusOK, response{
		Token: signedAccessToken,
	})
}

func (apiCfg *apiConfig) RevokeHandler(w http.ResponseWriter, r *http.Request) {
	tokenString, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	log.Printf("Token:%s", tokenString)
	if !found {
		respondWithError(w, http.StatusInternalServerError, "Couldn't get token")
		return
	}
	claimsStruct := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claimsStruct, func(token *jwt.Token) (interface{}, error) {
		return []byte(apiCfg.JwtSecret), nil
	})
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Token is invalid")
		return
	}
	issuer, err := token.Claims.GetIssuer()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't get issuer")
		return
	}
	if issuer == "chirpy-access" {
		respondWithError(w, http.StatusBadRequest, "Got Access-token")
		return
	}

	// userID, err := token.Claims.GetSubject()
	// if err != nil {
	// 	respondWithError(w, http.StatusInternalServerError, "Couldn't get user ID")
	// 	return
	// }
	// userIDInt, err := strconv.Atoi(userID)
	// if err != nil {
	// 	respondWithError(w, http.StatusInternalServerError, "Couldn't transform userid to int")
	// 	return
	// }
	// user, err := apiCfg.DB.GetUserByID(userIDInt)
	// if err != nil {
	// 	respondWithError(w, http.StatusInternalServerError, "Couldn't retrieve user")
	// 	return
	// }

	err = apiCfg.DB.RevokeToken(tokenString)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't revoke Token")
		return
	}

	w.WriteHeader(http.StatusOK)

	// userID, err := token.Claims.GetSubject()
	// if err != nil {
	// 	respondWithError(w, http.StatusInternalServerError, "Couldn't get user ID")
	// 	return
	// }
	// userIDInt, err := strconv.Atoi(userID)
	// if err != nil {
	// 	respondWithError(w, http.StatusInternalServerError, "Couldn't transform userid to int")
	// 	return
	// }
	// user, err := apiCfg.DB.GetUserByID(userIDInt)
	// if err != nil {
	// 	respondWithError(w, http.StatusInternalServerError, "Couldn't retrieve user")
	// }
	// user.RefreshToken
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

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits++
		next.ServeHTTP(w, r)
	})
}
