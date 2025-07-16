package main

import (
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"random"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/mailgun/mailgun-go/v4"
)

//go:embed templates/*
var templates embed.FS

type Claims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

type RegistrationData struct {
	Name    string
	Email   string
	OptOut  bool
	Error   string
	Success bool
}

type Config struct {
	AuthKey       string
	MailgunAPIKey string
	MailgunDomain string
	ServerURL     string
	ProxyAddr     string
	BindAddr      string
	CsrfToken     string
}

func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	_, err := random.Read(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	config := Config{
		AuthKey:       os.Getenv("AUTH_KEY"),
		MailgunAPIKey: os.Getenv("MAILGUN_API_KEY"),
		MailgunDomain: os.Getenv("MAILGUN_DOMAIN"),
		ServerURL:     os.Getenv("SERVER_URL"),
		ProxyAddr:     os.Getenv("PROXY_ADDR"),
		BindAddr:      os.Getenv("BIND_ADDR"),
	}

	if config.AuthKey == "" || config.MailgunAPIKey == "" || config.MailgunDomain == "" ||
		config.ServerURL == "" || config.ProxyAddr == "" || config.BindAddr == "" {
		log.Fatal("Missing required environment variables, any of: AUTH_KEY, MAILGUN_API_KEY, MAILGUN_DOMAIN, SERVER_URL, PROXY_ADDR, BIND_ADDR")
	}

	// Parse proxy URL
	proxyURL, err := url.Parse(config.ProxyAddr)
	if err != nil {
		log.Fatalf("Invalid proxy URL: %v", err)
	}

	// Initialize reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(proxyURL)

	// Initialize templates
	tmpl := template.Must(template.ParseFS(templates, "templates/*.html"))

	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		// Handle magic link callback
		tokenStr := r.URL.Query().Get("token")
		token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(config.AuthKey), nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(*Claims)
		if !ok {
			http.Error(w, "Invalid claims", http.StatusUnauthorized)
			return
		}

		// Set Auth cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "Auth",
			Value:    tokenStr,
			Path:     "/",
			Expires:  time.Now().Add(24 * time.Hour),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})

		// Redirect to original path or root
		redirectPath := "/"
		if path := r.URL.Query().Get("redirect"); path != "" && strings.HasPrefix(path, "/") {
			redirectPath = path
		}
		http.Redirect(w, r, redirectPath, http.StatusFound)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Check for valid JWT in Auth cookie
		cookie, err := r.Cookie("Auth")
		var email string
		if err == nil {
			token, err := jwt.ParseWithClaims(cookie.Value, &Claims{}, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return []byte(config.AuthKey), nil
			})
			if err == nil && token.Valid {
				if claims, ok := token.Claims.(*Claims); ok {
					email = claims.Email
				}
			}
		}

		if email != "" {
			// Valid JWT: add X-Auth-Email header and proxy
			r.Header.Set("X-Auth-Email", email)
			proxy.ServeHTTP(w, r)
			return
		}

		// No valid JWT: serve splash page
		if r.Method == http.MethodPost {
			return handleRegistration(w, r, config, tmpl)
		}
		data := RegistrationData{}
		if err := tmpl.ExecuteTemplate(w, "splash.html", data); err != nil {
			http.Error(w, "Template error", http.StatusInternalServerError)
		}
	})

	log.Printf("Starting server on %s", config.BindAddr)
	if err := http.ListenAndServe(config.BindAddr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func handleRegistration(w http.ResponseWriter, r *http.Request, config Config, tmpl *template.Template) {
	data := RegistrationData{
		Name:   r.FormValue("name"),
		Email:  r.FormValue("email"),
		OptOut: r.FormValue("optin") != "on",
	}

	if data.Name == "" || data.Email == "" {
		data.Error = "Name and email are required"
		tmpl.ExecuteTemplate(w, "splash.html", data)
		return
	}

	// Create JWT
	claims := &Claims{
		Email: data.Email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			Issuer:    config.ServerURL,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(config.AuthKey))
	if err != nil {
		data.Error = "Failed to create token"
		tmpl.ExecuteTemplate(w, "splash.html", data)
		return
	}

	// Send email with magic link
	mg := mailgun.NewMailgun(config.MailgunDomain, config.MailgunAPIKey)
	subject := "Login to our service"
	magicLink := fmt.Sprintf("%s/auth?token=%s", config.ServerURL, url.QueryEscape(tokenString))
	body := fmt.Sprintf("Hi %s,\n\nClick here to log in: %s\n\nThis link expires in 1 hour.", data.Name, magicLink)
	message := mg.NewMessage("no-reply@yourdomain.com", data.Name, subject, data.Email)
	message.SetText(body)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	_, _, err = mg.Send(ctx, message)
	if err != nil {
		data.Error = "Failed to send email"
		tmpl.ExecuteTemplate(w, "splash.html", data)
		return
	}

	// Optionally store opt-in status (e.g., in a database)
	if data.OptIn {
		log.Printf("User %s opted in to marketing", data.Email)
	}

	data.Success = true
	tmpl.ExecuteTemplate(w, "splash.html", data)
}
