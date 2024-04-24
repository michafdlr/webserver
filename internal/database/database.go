package database

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type DB struct {
	path string
	mu   *sync.RWMutex
}

type DBStructure struct {
	Chirps        map[int]Chirp           `json:"chirps"`
	Users         map[int]User            `json:"users"`
	RefreshTokens map[string]RefreshToken `json:"refresh_tokens"`
}

type User struct {
	ID           int    `json:"id"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	IsChirpyRed  bool   `json:"is_chirpy_red"`
}

type RefreshToken struct {
	//ID      string `json:"id"`
	Revoked bool `json:"revoked"`
}

type Chirp struct {
	ID       int    `json:"id"`
	Body     string `json:"body"`
	AuthorID int    `json:"author_id"`
}

func NewDB(path string) (*DB, error) {
	db := &DB{
		path: path,
		mu:   &sync.RWMutex{},
	}
	err := db.ensureDB()
	return db, err
}

func (db *DB) CreateChirp(body, secret string, header http.Header) (Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}
	tokenString, found := strings.CutPrefix(header.Get("Authorization"), "Bearer ")
	if !found {
		return Chirp{}, errors.New("authorization token missing")
	}
	claimsStruct := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claimsStruct, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return Chirp{}, errors.New("couldn't parse Claims")
	}
	issuer, err := token.Claims.GetIssuer()
	if err != nil {
		return Chirp{}, errors.New("couldn't get issuer")
	}
	if issuer == "chirpy-refresh" {
		return Chirp{}, errors.New("got refresh token")
	}
	userID, err := token.Claims.GetSubject()
	if err != nil {
		return Chirp{}, errors.New("couldn't get user")
	}
	userIDInt, err := strconv.Atoi(userID)
	if err != nil {
		return Chirp{}, errors.New("couldn't convert userid")
	}
	id := len(dbStructure.Chirps) + 1
	chirp := Chirp{
		ID:       id,
		Body:     body,
		AuthorID: userIDInt,
	}
	dbStructure.Chirps[id] = chirp

	err = db.writeDB(dbStructure)
	if err != nil {
		return Chirp{}, err
	}

	return chirp, nil
}

func (db *DB) DelteChirp(id int, secret string, header http.Header) (int, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return http.StatusInternalServerError, err
	}
	tokenString, found := strings.CutPrefix(header.Get("Authorization"), "Bearer ")
	if !found {
		return http.StatusInternalServerError, errors.New("authorization token missing")
	}
	claimsStruct := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claimsStruct, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return http.StatusInternalServerError, errors.New("couldn't parse Claims")
	}
	issuer, err := token.Claims.GetIssuer()
	if err != nil {
		return http.StatusInternalServerError, errors.New("couldn't get issuer")
	}
	if issuer == "chirpy-refresh" {
		return http.StatusUnauthorized, errors.New("got refresh token")
	}
	userID, err := token.Claims.GetSubject()
	if err != nil {
		return http.StatusInternalServerError, errors.New("couldn't get user")
	}
	userIDInt, err := strconv.Atoi(userID)
	if err != nil {
		return http.StatusInternalServerError, errors.New("couldn't convert userid")
	}
	chirp := dbStructure.Chirps[id]
	if chirp.AuthorID != userIDInt {
		return http.StatusForbidden, nil
	}
	delete(dbStructure.Chirps, id)

	err = db.writeDB(dbStructure)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func (db *DB) CreateRefreshToken(token string) (RefreshToken, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return RefreshToken{}, err
	}

	refreshToken := RefreshToken{
		//ID:      token,
		Revoked: false,
	}

	//id := len(dbStructure.RefreshTokens) + 1
	dbStructure.RefreshTokens[token] = refreshToken

	err = db.writeDB(dbStructure)
	if err != nil {
		return RefreshToken{}, err
	}

	return refreshToken, nil
}

func (db *DB) RevokeToken(token string) error {
	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}

	refreshToken := dbStructure.RefreshTokens[token]
	refreshToken.Revoked = true
	dbStructure.RefreshTokens[token] = refreshToken

	err = db.writeDB(dbStructure)
	if err != nil {
		return err
	}

	return nil
}

func (db *DB) CheckRevokedToken(token string) (bool, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return true, err
	}

	refreshToken := dbStructure.RefreshTokens[token]
	if refreshToken.Revoked {
		return true, nil
	}
	return false, nil
}

func (db *DB) UpdateUserToken(id int, token, ttype string) error {
	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}
	user := dbStructure.Users[id]
	if ttype == "access" {
		user.Token = token
	} else if ttype == "refresh" {
		user.RefreshToken = token
	}
	dbStructure.Users[id] = user
	err = db.writeDB(dbStructure)
	if err != nil {
		return err
	}
	return nil
}

func (db *DB) CreateUser(email, pw string) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	exists, err := db.CheckExistingUser(email)
	if err != nil {
		return User{}, err
	}
	if exists {
		return User{}, errors.New("User already exists")
	}
	encryptedPassword, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}

	id := len(dbStructure.Users) + 1
	user := User{
		ID:           id,
		Email:        email,
		Password:     string(encryptedPassword),
		Token:        "",
		RefreshToken: "",
		IsChirpyRed:  false,
	}

	dbStructure.Users[id] = user

	err = db.writeDB(dbStructure)
	if err != nil {
		return User{}, err
	}

	return user, nil
}

func (db *DB) UpgradeUser(id int) (int, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if id < 0 || id > len(dbStructure.Users) {
		return http.StatusNotFound, errors.New("couldn't find user")
	}
	user := dbStructure.Users[id]
	user.IsChirpyRed = true
	dbStructure.Users[id] = user

	err = db.writeDB(dbStructure)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func (db *DB) UpdateUser(id int, email, pw string) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}
	user := dbStructure.Users[id]
	encryptedPassword, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}

	user.Email = email
	user.Password = string(encryptedPassword)

	dbStructure.Users[id] = user

	err = db.writeDB(dbStructure)
	if err != nil {
		return User{}, err
	}

	return user, nil
}

func (db *DB) CheckExistingUser(email string) (bool, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return true, err
	}

	for _, user := range dbStructure.Users {
		if user.Email == email {
			return true, nil
		}
	}
	return false, nil
}

func (db *DB) GetUserByEmail(email string) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	for _, user := range dbStructure.Users {
		if user.Email == email {
			return user, nil
		}
	}
	return User{}, errors.New("User does not exist")
}

func (db *DB) GetUserByID(id int) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}
	if id > len(dbStructure.Users) {
		return User{}, errors.New("ID not present")
	}
	return dbStructure.Users[id], nil
}

func (db *DB) GetChirps() ([]Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return nil, err
	}

	chirps := make([]Chirp, 0, len(dbStructure.Chirps))
	for _, chirp := range dbStructure.Chirps {
		chirps = append(chirps, chirp)
	}

	return chirps, nil
}

func (db *DB) createDB() error {
	dbStructure := DBStructure{
		Chirps:        map[int]Chirp{},
		Users:         map[int]User{},
		RefreshTokens: map[string]RefreshToken{},
	}
	return db.writeDB(dbStructure)
}

func (db *DB) ensureDB() error {
	_, err := os.ReadFile(db.path)
	if errors.Is(err, os.ErrNotExist) {
		return db.createDB()
	}
	return err
}

func (db *DB) loadDB() (DBStructure, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	dbStructure := DBStructure{}
	dat, err := os.ReadFile(db.path)
	if errors.Is(err, os.ErrNotExist) {
		return dbStructure, err
	}
	err = json.Unmarshal(dat, &dbStructure)
	if err != nil {
		return dbStructure, err
	}

	return dbStructure, nil
}

func (db *DB) writeDB(dbStructure DBStructure) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	dat, err := json.Marshal(dbStructure)
	if err != nil {
		return err
	}

	err = os.WriteFile(db.path, dat, 0600)
	if err != nil {
		return err
	}
	return nil
}
