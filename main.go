package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type FormData map[string]interface{}

type GmailMessage struct {
	Raw string `json:"raw"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

var (
	currentAccessToken string
	tokenMutex         sync.RWMutex
	tokenExpiry        time.Time
)

func main() {
	// refresh the token to start with a fesh one
	refreshAccessToken()

	// Start token refresh goroutine
	go tokenRefreshLoop()

	http.HandleFunc("/skinnyform/send", handleFormSubmission)

	port := os.Getenv("SKINNYFORM_PORT")
	if port == "" {
		port = "3000"
	}

	log.Printf("Server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleFormSubmission(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	var formData FormData
	if err := json.NewDecoder(r.Body).Decode(&formData); err != nil {
		log.Printf("Error parsing form data: %v", err)
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	log.Printf("Received form data: %v", formData)

	// Build email message
	message := buildEmailMessage(formData)

	// Send email via Gmail API
	if err := sendGmailAPI(message); err != nil {
		log.Printf("Error sending email: %v", err)
		http.Error(w, fmt.Sprintf("Error sending email: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "Email sent successfully"})
}

func buildEmailMessage(formData FormData) string {
	// Helpers
	get := func(key string) string {
		if v, ok := formData[key]; ok {
			if s, ok := v.(string); ok {
				return strings.TrimSpace(s)
			}
		}
		return ""
	}

	// Pull the fields we care about
	name := get("name")
	replyTo := strings.TrimPrefix(get("_replyto"), "mailto:") // strip mailto: if present
	message := get("message")
	subject := get("_subject")
	if subject == "" {
		subject = "Contact Form Submission"
	}

	// Build a nice plain-text body
	var body strings.Builder
	if name != "" {
		body.WriteString("Name: " + name + "\n")
	}
	if replyTo != "" {
		body.WriteString("Reply-To: " + replyTo + "\n")
	}
	body.WriteString("\nMessage:\n" + message + "\n")

	// RFC 2822 message
	from := os.Getenv("EMAIL_USER")
	to := os.Getenv("EMAIL_TO")
	return fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nReply-To: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
		from, to, subject, replyTo, body.String())
}

func sendGmailAPI(message string) error {
	// Get current access token
	tokenMutex.RLock()
	accessToken := currentAccessToken
	tokenMutex.RUnlock()

	if accessToken == "" {
		return fmt.Errorf("access token not available")
	}

	// Base64 encode the message (URL-safe)
	encodedMessage := base64URLEncode([]byte(message))

	// Create request body
	gmailMsg := GmailMessage{Raw: encodedMessage}
	jsonData, err := json.Marshal(gmailMsg)
	if err != nil {
		return fmt.Errorf("error marshaling message: %v", err)
	}

	// Make API request
	req, err := http.NewRequest("POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/send", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusUnauthorized {
		// Token might be expired, trigger refresh
		log.Println("Access token expired, triggering refresh")
		if err := refreshAccessToken(); err != nil {
			return fmt.Errorf("failed to refresh token while sending email: %v", err)
		}
		// Retry with new token
		return sendGmailAPI(message)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Gmail API error (status %d): %s", resp.StatusCode, string(body))
	}

	log.Printf("Email sent successfully: %s", string(body))
	return nil
}

// Base64 URL encoding (RFC 4648)
func base64URLEncode(data []byte) string {
	const base64Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	encoded := make([]byte, (len(data)+2)/3*4)

	var j int
	for i := 0; i < len(data); i += 3 {
		b := uint32(data[i]) << 16
		if i+1 < len(data) {
			b |= uint32(data[i+1]) << 8
		}
		if i+2 < len(data) {
			b |= uint32(data[i+2])
		}

		for k := 0; k < 4 && j < len(encoded); k++ {
			encoded[j] = base64Table[(b>>uint(18-k*6))&0x3F]
			j++
		}
	}

	// Remove padding
	result := string(encoded)
	return strings.TrimRight(result, "=")
}

// tokenRefreshLoop periodically refreshes the access token
func tokenRefreshLoop() {
	for {
		// Sleep until 5 minutes before token expires
		tokenMutex.RLock()
		sleepDuration := time.Until(tokenExpiry) - 5*time.Minute
		tokenMutex.RUnlock()

		if sleepDuration > 0 {
			log.Printf("Next token refresh in %v", sleepDuration)
			time.Sleep(sleepDuration)
		}

		if err := refreshAccessToken(); err != nil {
			log.Printf("Error refreshing token: %v. Retrying in 1 minute...", err)
			time.Sleep(1 * time.Minute)
		}
	}
}

// refreshAccessToken uses the refresh token to get a new access token
func refreshAccessToken() error {
	log.Printf("about to refresh at")

	clientID := os.Getenv("GMAIL_CLIENT")
	clientSecret := os.Getenv("GMAIL_SECRET")
	refreshToken := os.Getenv("GMAIL_REFRESH")

	if clientID == "" || clientSecret == "" || refreshToken == "" {
		log.Printf("Error cannot refresh access token, missing credentials (CLIENT_ID, CLIENT_SECRET, or REFRESH_TOKEN)")
		return fmt.Errorf("missing OAuth credentials (CLIENT_ID, CLIENT_SECRET, or REFRESH_TOKEN)")
	}

	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("refresh_token", refreshToken)
	data.Set("grant_type", "refresh_token")

	resp, err := http.PostForm("https://oauth2.googleapis.com/token", data)
	if err != nil {
		log.Printf("Error making refesh request: %v", err)
		return fmt.Errorf("error making refresh request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		log.Printf("Error token refesh failed (status %d): %s", resp.StatusCode, string(body))
		return fmt.Errorf("token refresh failed (status %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		log.Printf("Error parsing the token response: %v", err)
		return fmt.Errorf("error parsing token response: %v", err)
	}

	// Update the access token
	tokenMutex.Lock()
	currentAccessToken = tokenResp.AccessToken
	tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	tokenMutex.Unlock()

	log.Printf("Access token refreshed successfully. Expires at: %v", tokenExpiry)
	return nil
}
