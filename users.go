package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func (apiCfg *apiConfig) PostUsersHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	type response struct {
		Email       string `json:"email"`
		ID          int    `json:"id"`
		IsChirpyRed bool   `json:"is_chirpy_red"`
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

	respondWithJSON(w, http.StatusCreated, response{
		Email:       user.Email,
		ID:          user.ID,
		IsChirpyRed: user.IsChirpyRed,
	})
}

func (apiCfg *apiConfig) PutUsersHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	type response struct {
		Email       string `json:"email"`
		ID          int    `json:"id"`
		IsChirpyRed bool   `json:"is_chirpy_red"`
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

	respondWithJSON(w, http.StatusOK, response{
		Email:       user.Email,
		ID:          user.ID,
		IsChirpyRed: user.IsChirpyRed,
	})
}

func (apiCfg *apiConfig) ValidateUsersHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		//Expires  int    `json:"expires_in_seconds"`
	}
	type response struct {
		Email       string `json:"email"`
		ID          int    `json:"id"`
		IsChirpyRed bool   `json:"is_chirpy_red"`
		Token       string `json:"token"`
	}
	// type responseToken struct {
	// 	Token string `json:"token"`
	// 	RefreshToken string `json:"refresh_token"`
	// }
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
	err = apiCfg.DB.UpdateUserToken(userID, signedRefreshToken, "refresh")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't update refresh token")
	}
	_, err = apiCfg.DB.CreateRefreshToken(signedRefreshToken)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Couldn't create refresh token in DB")
		return
	}

	respondWithJSON(w, http.StatusOK, response{
		Email:       user.Email,
		ID:          user.ID,
		IsChirpyRed: user.IsChirpyRed,
		Token:       signedAccessToken,
	})
}

func (apiCfg *apiConfig) UpgradeHandler(w http.ResponseWriter, r *http.Request) {

	type parameters struct {
		Event string `json:"event"`
		Data  struct {
			UserID int `json:"user_id"`
		} `json:"data"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters")
		return
	}
	log.Println("Decoding successfull")
	if params.Event != "user.upgraded" {
		log.Print(params.Event)
		respondWithJSON(w, http.StatusOK, "no valid event")
		return
	}
	log.Println("passed event")
	userid := params.Data.UserID
	log.Printf("%d", userid)
	status, err := apiCfg.DB.UpgradeUser(userid, apiCfg.ApiKey, r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't find user")
		return
	}
	w.WriteHeader(status)
}
