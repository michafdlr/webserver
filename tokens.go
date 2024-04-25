package main

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

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

	err = apiCfg.DB.RevokeToken(tokenString)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't revoke Token")
		return
	}

	w.WriteHeader(http.StatusOK)
}
