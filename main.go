package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// APP ID or CLIENT ID
var GITHUBAPPID int64 = 1218392

func getEnvOrFail(key string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		fmt.Printf("Missing environment variable: %s\n", key)
		os.Exit(1)
	}
	return value
}

func generateJWTtoken() string {
	privateKey, err := os.ReadFile("private.pem")
	if err != nil {
		fmt.Printf("error reading file: %s\n", err)
		os.Exit(1)
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		fmt.Printf("could not parse private key: %s", err)
		os.Exit(1)
	}
	iss := time.Now().Add(-30 * time.Second).Truncate(time.Second)
	exp := iss.Add(2 * time.Minute)
	claims := &jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(iss),
		ExpiresAt: jwt.NewNumericDate(exp),
		Issuer:    strconv.FormatInt(GITHUBAPPID, 10),
	}
	token, _ := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	return token
}

func generateInstallationToken() string {
	// find out the installation ID (64582855) or
	// url := "https://api.github.com/app/installations"
	// req, err := http.NewRequest(http.MethodGet, url, nil)
	url := "https://api.github.com/app/installations/64650729/access_tokens"
	req, err := http.NewRequest(http.MethodPost, url, nil)
	// url := "https://api.github.com/app/installations"
	// req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Printf("github post: new request: %s\n", err)
		os.Exit(1)
	}
	req.Header.Add("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Authorization", "Bearer "+generateJWTtoken())

	client := &http.Client{Timeout: time.Second * 5}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("http client Do: %s\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println(resp.Header.Get("X-RateLimit-Limit"))
	fmt.Println(resp.Header.Get("X-RateLimit-Remaining"))
	fmt.Println(string(body))
	var token struct {
		Value string `json:"token"`
	}
	if err := json.Unmarshal(body, &token); err != nil {
		fmt.Printf("error: json unmarshal: %s\n", err)
		os.Exit(1)
	}
	return token.Value
}

func main() {
	// load the usual user GitHub token from enviroment
	// just to show that from cogito point of view; both approaches
	// are equivalent. One doesn't need to update the cogito code to
	// handle github apps.. To support GitHub apps, we generate the token
	// add pass it around in the same way as the existing approach
	// with user token.
	// token := getEnvOrFail("GH_TOKEN")
	token := generateInstallationToken()
	// API: GET /repos/{owner}/{repo}/commits/master/statuses
	url := "https://api.github.com/repos/pix4d/cogito-test-read-write/commits/stable/statuses"
	// API: POST /repos/{owner}/{repo}/statuses/sha
	//url := "https://api.github.com/repos/aliculPix4D/test-gh-status-app/statuses/5dd7ad52911cd6f2bf9ac7ce0707021fb5e2ce4d"
	//url := "https://api.github.com/rate_limit"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	//req, err := http.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"state":"success"}`))
	if err != nil {
		fmt.Printf("github get: new request: %s\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: time.Second * 5}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("http client Do: %s\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(resp.Header.Get("X-RateLimit-Limit"))
	fmt.Println(resp.Header.Get("X-RateLimit-Remaining"))
	fmt.Println(string(body))
}
