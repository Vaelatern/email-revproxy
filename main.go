package main

import (
	"bytes"
	"embed"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"github.com/Vaelatern/email-revproxy/internal/aerouter"
	"github.com/golang-jwt/jwt/v5"
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
)

func dbg(a string) {
	log.Println(a)
}

//go:embed templates/*
var templates embed.FS

type WebTemplateArgs struct {
	Name       string
	Email      string
	OptOut     bool
	Error      string
	Success    bool
	CsrfToken  string
	TriedEmail bool
}

type EmailPayload struct {
	Name           string
	Email          string
	Token          string
	HttpPathAtSend string
}

// https://pkg.go.dev/net/smtp#SendMail
type EmailConf struct {
	Addr           string `env:"ENDPOINT" yaml:"endpoint" json:"endpoint" env-required:"true"`
	User           string `env:"USER" env-required:"true"`
	Pass           string `env:"PASS" env-required:"true"`
	From           string `env:"FROM" env-required:"true"`
	Bcc            []string
	MessageTplName string `env:"MESSAGE_TEMPLATE_NAME" yaml:"message-template-name" json:"message-template-name"`
	MessageTpl     string `env:"MESSAGE_TEMPLATE" yaml:"message-template" json:"message-template"`
}

type ClientDetect struct {
	UseRemoteAddr bool `env:"USE_REMOTE_ADDR" yaml:"use-remote-addr" json:"use-remote-addr"`
}

type Config struct {
	AuthKey   string       `env:"AUTH_KEY" yaml:"auth-key" json:"auth-key" env-required:"true"`
	ProxyAddr string       `env:"PROXY_ADDR" yaml:"proxy-address" json:"proxy-address" env-required:"true"`
	BindAddr  string       `env:"BIND_ADDR" yaml:"bind-address" json:"bind-address" env-default:":8080"`
	Smtp      EmailConf    `env-prefix:"SMTP" yaml:"smtp" json:"smtp"`
	Detect    ClientDetect `env-prefix:"CLIENT_DETECT" yaml:"client-detect" json:"client-detect"`
}

func (c Config) requestCSRFIp(r *http.Request) string {
	if c.Detect.UseRemoteAddr {
		return strings.Split(r.RemoteAddr, ":")[0]
	}
	// Get IP from X-Forwarded-For header
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		log.Fatal("Misconfiguration - proxy did not pass X-Forwarded-For so perhaps an attacker can abuse this")
	}
	return ip
}

func (c Config) generateJWT(claims jwt.MapClaims, expireIn time.Duration) (string, error) {
	// Create JWT claims
	claims["exp"] = time.Now().Add(expireIn).Unix()

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token with a secret key
	signedToken, err := token.SignedString([]byte(c.AuthKey))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

type jwtExtractFn func(claims jwt.MapClaims) (bool, string, error)

func (c Config) validateJWT(tokenString string, okCB jwtExtractFn) (bool, string, error) {
	if tokenString == "" {
		return false, "", nil // No token provided
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return false, jwt.ErrSignatureInvalid
		}
		// Provide the same secret key used for signing
		return []byte(c.AuthKey), nil
	})
	if err != nil {
		return false, "", err
	}

	// Check if token is valid and not expired
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return okCB(claims)
	}

	return false, "", nil
}

func (c Config) generateCSRFToken(r *http.Request) (string, error) {
	ip := c.requestCSRFIp(r)
	return c.generateJWT(jwt.MapClaims{
		"ip": ip,
	}, time.Hour*24*7) // expire after a week
}

func (c Config) verifyCSRFToken(r *http.Request) (bool, string, error) {
	// Get CSRF token from form field
	tokenString := r.FormValue("_csrf")
	return c.validateJWT(tokenString, func(claims jwt.MapClaims) (bool, string, error) {
		ip := c.requestCSRFIp(r)
		// Verify IP matches the claim
		if claimIP, ok := claims["ip"].(string); ok && claimIP == ip {
			return true, claims["ip"].(string), nil
		}
		return false, "", nil
	})
}

func getConfig() Config {
	config := Config{}

	err := cleanenv.ReadConfig("config.yml", &config)
	if err != nil {
		log.Fatalf("Failed loading configuration: %v", err)
	}

	return config
}

func (c Config) revProxy() *httputil.ReverseProxy {
	// Parse proxy URL
	proxyURL, err := url.Parse(c.ProxyAddr)
	if err != nil {
		log.Fatalf("Invalid proxy URL: %v", err)
	}

	// Initialize reverse proxy
	return httputil.NewSingleHostReverseProxy(proxyURL)
}

func (c Config) extractClaimIP(r *http.Request) jwtExtractFn {
	return func(claims jwt.MapClaims) (bool, string, error) {
		ip := c.requestCSRFIp(r)
		// Verify IP matches the claim
		if claimIP, ok := claims["ip"].(string); ok && claimIP == ip {
			return true, claims["ip"].(string), nil
		}
		return false, "", nil
	}
}

func (c Config) extractClaimEmail(r *http.Request) jwtExtractFn {
	return func(claims jwt.MapClaims) (bool, string, error) {
		if email, ok := claims["email"].(string); ok && email != "" {
			return true, claims["email"].(string), nil
		}
		return false, "", nil
	}
}

func (c Config) shortcutAuthed(next http.Handler) http.Handler {
	proxy := c.revProxy()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := r.Cookie("Auth")
		if err == nil {
			if ok, email, err := c.validateJWT(tokenString.Value, c.extractClaimEmail(r)); ok &&
				err == nil && email != "" {
				dbg("valid jwt, proxytime")
				// Valid JWT: add X-Auth-Email header and proxy
				r.Header.Set("X-Auth-Email", email)
				proxy.ServeHTTP(w, r)
				return
			}
		}
		// continue chain if auth shortcut didn't work
		dbg("authed? no. descending.")
		next.ServeHTTP(w, r)
		return
	})

}

func (c Config) generateAuthToken(email string) (string, error) {
	token, err := c.generateJWT(jwt.MapClaims{
		"email": email,
	}, time.Hour*24*7) // expire after a week
	if err != nil {
		return "", err
	}
	return token, nil
}

func (c Config) setAuthCookie(w http.ResponseWriter, email string) error {
	if token, err := c.generateAuthToken(email); err == nil {
		http.SetCookie(w, &http.Cookie{
			Name:     "Auth",
			Value:    token,
			Path:     "/",
			Expires:  time.Now().Add(time.Hour * 24 * 7),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
	}
	return nil
}

func (c Config) shortcutAuthing(next http.Handler) http.Handler {
	proxy := c.revProxy()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.URL.Query().Get("token") // token provided, try parsing it
		if ok, email, err := c.validateJWT(tokenString, c.extractClaimEmail(r)); ok && err == nil && email != "" {
			dbg("valid jwt, authing")
			// Record this for later
			c.setAuthCookie(w, email)
			// Valid JWT: add X-Auth-Email header and proxy
			r.Header.Set("X-Auth-Email", email)
			proxy.ServeHTTP(w, r)
			return
		} else { // continue chain if auth shortcut didn't work
			dbg("authing? no. descending.")
			next.ServeHTTP(w, r)
			return
		}
		dbg("authing? no. wtfing")
		return
	})
}

func (c Config) sendRegistration(w http.ResponseWriter, r *http.Request, tmpl *template.Template) error {
	email := r.FormValue("email")
	dbg("sending email to " + email)
	if token, err := c.generateAuthToken(email); err == nil {
		if err != nil {
			return err
		}
		data := EmailPayload{
			HttpPathAtSend: r.RequestURI,
			Name:           r.FormValue("name"),
			Email:          r.FormValue("email"),
			Token:          token,
		}
		where := c.Smtp.Addr
		auth := smtp.PlainAuth("", c.Smtp.User, c.Smtp.Pass, c.Smtp.Addr)
		from := c.Smtp.From
		to := append(c.Smtp.Bcc, r.FormValue("email"))
		msg := bytes.NewBuffer([]byte{})
		if c.Smtp.MessageTplName != "" {
			err := tmpl.ExecuteTemplate(msg, c.Smtp.MessageTplName, data)
			if err != nil {
				return err
			}
		} else {
			finalTpl, err := tmpl.Parse(c.Smtp.MessageTpl)
			if err != nil {
				return err
			}
			err = finalTpl.Execute(msg, data)
			if err != nil {
				return err
			}
		}
		msgBytes := bytes.Replace(msg.Bytes(), []byte("\n"), []byte("\r\n"), -1)
		dbg("ready to send email")
		dbg(string(msgBytes))
		return smtp.SendMail(where, auth, from, to, msgBytes)
	}
	return nil
}

// root is presented a clean path. By the time we get here, a user is not authenticated.
// If they are POSTing, they are requesting an email be sent to them, maybe.
// If they are anything else, they are unauthenticated and should be presented with a form.
func (c Config) posted() http.HandlerFunc {
	// Initialize templates
	tmpl := template.Must(template.ParseFS(templates, "templates/*"))
	return func(w http.ResponseWriter, r *http.Request) {
		dbg("posted so handling that")
		passParams := WebTemplateArgs{}
		ok, ip, err := c.verifyCSRFToken(r)
		if ok && err == nil && ip != "" {
			subtpl, err := tmpl.Clone()
			if err != nil {
				http.Error(w, "Template Clone error", http.StatusInternalServerError)
			}
			if err := c.sendRegistration(w, r, subtpl); err == nil {
				dbg("Tried to email!")
				passParams.TriedEmail = true
			} else {
				dbg(err.Error())
				passParams.Error = err.Error()
			}
		}

		tok, err := c.generateCSRFToken(r)
		if err != nil {
			http.Error(w, "CSRF error", http.StatusInternalServerError)
		} else {
			passParams.CsrfToken = tok
		}

		if err := tmpl.ExecuteTemplate(w, "splash.html", passParams); err != nil {
			http.Error(w, "Template error", http.StatusInternalServerError)
		}
	}
}

func (c Config) root() http.HandlerFunc {
	// Initialize templates
	tmpl := template.Must(template.ParseFS(templates, "templates/*"))
	return func(w http.ResponseWriter, r *http.Request) {
		dbg("splash and login")
		templateArgs := WebTemplateArgs{}
		tok, err := c.generateCSRFToken(r)
		if err != nil {
			http.Error(w, "CSRF error", http.StatusInternalServerError)
		} else {
			templateArgs.CsrfToken = tok
		}
		// nice splash and login page
		if err := tmpl.ExecuteTemplate(w, "splash.html", templateArgs); err != nil {
			http.Error(w, "Template error", http.StatusInternalServerError)
		}
	}
}

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	config := getConfig()

	r := aerouter.NewRouter()
	r.Use(config.shortcutAuthed)
	r.Use(config.shortcutAuthing)
	r.HandleFunc("POST /", config.posted())
	r.HandleFunc("/", config.root())
	log.Printf("[emailproxy] Listening on %s\n", config.BindAddr)
	dbg("Debug on")
	log.Fatal(http.ListenAndServe(config.BindAddr, r))
}
