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
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	// Server
	Port string // Optional, Default: 3000

	// Gmail
	GmailClient  string // Required
	GmailSecret  string // Required
	GmailRefresh string // Required
	EmailUser    string // Required
	EmailTo      string // Required

	// Security
	RateLimitWindow    time.Duration   // Optional, Default: 1h
	RateLimitMax       int             // Optional, Default: 3
	BlacklistedDomains map[string]bool // Optional, Default: []
	AllowedOrigin      string          // Optional, Default: *
}

type FormData map[string]interface{}

type GmailMessage struct {
	Raw string `json:"raw"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

var (
	config Config

	currentAccessToken string
	tokenMutex         sync.RWMutex
	tokenExpiry        time.Time

	rateLimitMap   = make(map[string][]time.Time)
	rateLimitMutex sync.Mutex
)

func main() {
	// initial setup
	initConfig()
	refreshAccessToken()

	// reocurring tasks
	go tokenRefreshLoop()
	go rateLimitCleanup()

	// configure and start server
	http.HandleFunc("/skinnyform/health", handleHealth)
	http.HandleFunc("/skinnyform/send", handleFormSubmission)

	log.Printf("Server starting on port %s", config.Port)
	log.Fatal(http.ListenAndServe(":"+config.Port, nil))
}

func initConfig() {
	// Server
	config.Port = getEnvOrDefault("PORT", "3000")

	// Gmail
	config.GmailClient = os.Getenv("GMAIL_CLIENT")
	config.GmailSecret = os.Getenv("GMAIL_SECRET")
	config.GmailRefresh = os.Getenv("GMAIL_REFRESH")
	config.EmailUser = os.Getenv("EMAIL_USER")
	config.EmailTo = os.Getenv("EMAIL_TO")

	// Security
	var err error
	windowStr := getEnvOrDefault("RATE_LIMIT_WINDOW", "1h")
	config.RateLimitWindow, err = time.ParseDuration(windowStr)
	if err != nil {
		log.Printf("Invalid RATE_LIMIT_WINDOW '%s', using default 1h", windowStr)
		config.RateLimitWindow = 1 * time.Hour
	}

	maxStr := getEnvOrDefault("RATE_LIMIT_MAX", "3")
	config.RateLimitMax, err = strconv.Atoi(maxStr)
	if err != nil || config.RateLimitMax < 1 {
		log.Printf("Invalid RATE_LIMIT_MAX '%s', using default 3", maxStr)
		config.RateLimitMax = 3
	}

	config.BlacklistedDomains = make(map[string]bool)
	blacklistStr := os.Getenv("BLACKLIST_DOMAINS")
	if blacklistStr != "" {
		domains := strings.Split(blacklistStr, ",")
		for _, domain := range domains {
			domain = strings.TrimSpace(strings.ToLower(domain))
			if domain != "" {
				config.BlacklistedDomains[domain] = true
			}
		}
	}

	config.AllowedOrigin = getEnvOrDefault("ALLOWED_ORIGIN", "*")

	// Validate Configuration
	if config.EmailUser == "" || config.EmailTo == "" {
		log.Fatal("EMAIL_USER and EMAIL_TO must be set")
	}
	if config.GmailClient == "" || config.GmailSecret == "" || config.GmailRefresh == "" {
		log.Fatal("Gmail OAuth credentials (GMAIL_CLIENT, GMAIL_SECRET, GMAIL_REFRESH) must be set")
	}

	// Log final configuration
	log.Printf("Configuration loaded:")
	log.Printf("  Port: %s", config.Port)
	log.Printf("  Email User: %s", config.EmailUser)
	log.Printf("  Email To: %s", config.EmailTo)
	log.Printf("  Rate Limit: %d requests per %v", config.RateLimitMax, config.RateLimitWindow)
	if len(config.BlacklistedDomains) > 0 {
		log.Printf("  Blacklisted Domains: %d configured", len(config.BlacklistedDomains))
		for domain := range config.BlacklistedDomains {
			log.Printf("    - %s", domain)
		}
	} else {
		log.Printf("  Blacklisted Domains: none")
	}
	log.Printf("  Allowed Origin: %s", config.AllowedOrigin)
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	// TODO: if token is failed to refresh or other issue, fail health check
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleFormSubmission(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", config.AllowedOrigin)
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

	// ============ SPAM PROTECTION ============

	// 1. Honeypot check
	if website, ok := formData["website"].(string); ok && website != "" {
		log.Printf("Honeypot triggered - rejecting spam submission")
		// Return success to not tip off the bot
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "Email sent successfully"})
		return
	}

	// 2. Basic validation
	name, _ := formData["name"].(string)
	message, _ := formData["message"].(string)
	replyTo, _ := formData["_replyto"].(string)

	if strings.TrimSpace(name) == "" || strings.TrimSpace(message) == "" || strings.TrimSpace(replyTo) == "" {
		log.Printf("Missing required fields")
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	if len(message) < 10 {
		log.Printf("Message too short - likely spam")
		http.Error(w, "Message too short", http.StatusBadRequest)
		return
	}

	// 3. Check blacklisted domains
	replyTo = strings.TrimPrefix(replyTo, "mailto:")
	if isBlacklistedEmail(replyTo) {
		log.Printf("Blacklisted domain detected: %s", replyTo)
		// Return success to not tip off the spammer
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "Email sent successfully"})
		return
	}

	// 4. Rate limiting by IP
	clientIP := getClientIP(r)
	if rateLimitExceeded(clientIP) {
		log.Printf("Rate limit exceeded for IP: %s", clientIP)
		http.Error(w, "Too many requests. Please try again later.", http.StatusTooManyRequests)
		return
	}

	// =========================================

	log.Printf("Received form data: %v", formData)

	// Build email message
	emailMessage := buildEmailMessage(formData)

	// Send email via Gmail API
	if err := sendGmailAPI(emailMessage); err != nil {
		log.Printf("Error sending email: %v", err)
		http.Error(w, fmt.Sprintf("Error sending email: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "Email sent successfully"})
}

func isBlacklistedEmail(email string) bool {
	email = strings.ToLower(strings.TrimSpace(email))

	// Extract domain from email
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		log.Printf("Error parsing email: %s", email)
		return false
	}

	domain := parts[1]
	return config.BlacklistedDomains[domain]
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (if behind a proxy/load balancer)
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Take the first IP in the list
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	// Remove port if present
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

func rateLimitExceeded(ip string) bool {
	rateLimitMutex.Lock()
	defer rateLimitMutex.Unlock()

	now := time.Now()

	// Get timestamps for this IP
	timestamps, exists := rateLimitMap[ip]
	if !exists {
		rateLimitMap[ip] = []time.Time{now}
		return false
	}

	// Remove timestamps outside the time window
	var recentTimestamps []time.Time
	for _, ts := range timestamps {
		if now.Sub(ts) < config.RateLimitWindow {
			recentTimestamps = append(recentTimestamps, ts)
		}
	}

	// Check if limit exceeded
	if len(recentTimestamps) >= config.RateLimitMax {
		return true
	}

	// Add current timestamp
	recentTimestamps = append(recentTimestamps, now)
	rateLimitMap[ip] = recentTimestamps

	return false
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
	subject := "Contact Form Submission"

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
	return fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nReply-To: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
		config.EmailUser, config.EmailTo, subject, replyTo, body.String())
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

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
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

func refreshAccessToken() error {
	log.Printf("Refreshing access token...")

	if config.GmailClient == "" || config.GmailSecret == "" || config.GmailRefresh == "" {
		log.Printf("Error cannot refresh access token, missing credentials (CLIENT_ID, CLIENT_SECRET, or REFRESH_TOKEN)")
		return fmt.Errorf("missing OAuth credentials (CLIENT_ID, CLIENT_SECRET, or REFRESH_TOKEN)")
	}

	data := url.Values{}
	data.Set("client_id", config.GmailClient)
	data.Set("client_secret", config.GmailSecret)
	data.Set("refresh_token", config.GmailRefresh)
	data.Set("grant_type", "refresh_token")

	resp, err := http.PostForm("https://oauth2.googleapis.com/token", data)
	if err != nil {
		log.Printf("Error making refresh request: %v", err)
		return fmt.Errorf("error making refresh request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		log.Printf("Error token refresh failed (status %d): %s", resp.StatusCode, string(body))
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

func rateLimitCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		rateLimitMutex.Lock()
		now := time.Now()
		for ip, timestamps := range rateLimitMap {
			var recent []time.Time
			for _, ts := range timestamps {
				if now.Sub(ts) < config.RateLimitWindow {
					recent = append(recent, ts)
				}
			}
			if len(recent) == 0 {
				delete(rateLimitMap, ip)
			} else {
				rateLimitMap[ip] = recent
			}
		}
		rateLimitMutex.Unlock()
	}
}
