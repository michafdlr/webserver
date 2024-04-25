package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

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
	authorId := r.URL.Query().Get("author_id")
	sorting := r.URL.Query().Get("sort")
	if sorting == "" {
		sorting = "asc"
	}

	chirps := []Chirp{}
	if authorId == "" {
		for _, dbChirp := range dbChirps {
			chirps = append(chirps, Chirp{
				ID:       dbChirp.ID,
				Body:     dbChirp.Body,
				AuthorID: dbChirp.AuthorID,
			})
		}
	} else {
		authorIdInt, err := strconv.Atoi(authorId)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "couldn't convert userid")
			return
		}
		for _, dbChirp := range dbChirps {
			if dbChirp.AuthorID == authorIdInt {
				chirps = append(chirps, Chirp{
					ID:       dbChirp.ID,
					Body:     dbChirp.Body,
					AuthorID: dbChirp.AuthorID,
				})
			}
		}
	}
	if sorting == "asc" {
		sort.Slice(chirps, func(i, j int) bool {
			return chirps[i].ID < chirps[j].ID
		})
	} else {
		sort.Slice(chirps, func(i, j int) bool {
			return chirps[i].ID > chirps[j].ID
		})
	}

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

func (apiConfig *apiConfig) DeleteChirpHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid ID")
		return
	}
	status, err := apiConfig.DB.DelteChirp(id, apiConfig.JwtSecret, r.Header)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "couldn't delete chirp")
		return
	}
	w.WriteHeader(status)
}
