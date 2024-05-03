package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"golang.org/x/crypto/scrypt"
)

var (
	privateKey []byte
	publicKey  []byte
	modulus    *big.Int
	exponent   int
)

const salt_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func genSalt(length int) string {
	if length <= 0 {
		log.Println("[ERROR] Known in genSalt() at", strconv.FormatInt(time.Now().Unix(), 10)+":", "Salt length must be at least one.")
	}

	salt := make([]byte, length)
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		log.Println("[ERROR] Unknown in genSalt() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
	}

	for i := range salt {
		salt[i] = salt_chars[int(randomBytes[i])%len(salt_chars)]
	}
	return string(salt)
}

func sha256Base64(s string) string {
	hashed := sha256.Sum256([]byte(s))
	encoded := base64.URLEncoding.EncodeToString(hashed[:])
	encoded = strings.TrimRight(encoded, "=")
	return encoded
}

func hash(password, salt string) string {
	passwordBytes := []byte(password)
	saltBytes := []byte(salt)

	derivedKey, _ := scrypt.Key(passwordBytes, saltBytes, 32768, 8, 1, 64)

	hashString := fmt.Sprintf("scrypt:32768:8:1$%s$%s", salt, hex.EncodeToString(derivedKey))
	return hashString
}

func verifyHash(werkzeug_hash, password string) bool {
	parts := strings.Split(werkzeug_hash, "$")
	if len(parts) != 3 || parts[0] != "scrypt:32768:8:1" {
		return false
	}
	salt := parts[1]

	computedHash := hash(password, salt)

	return werkzeug_hash == computedHash
}

func get_db_connection() *sql.DB {
	db, _ := sql.Open("sqlite3", "database.db")
	return db
}

func get_user(id int) (string, string, string, string, bool) {
	norows := false
	conn := get_db_connection()
	defer func(conn *sql.DB) {
		err := conn.Close()
		if err != nil {
			log.Println("[ERROR] Unknown in get_user() defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			norows = true
		}
	}(conn)
	var created, username, password, uniqueid string
	err := conn.QueryRow("SELECT created, username, uniqueid, password FROM users WHERE id = ? LIMIT 1", id).Scan(&created, &username, &uniqueid, &password)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			norows = true
		} else {
			log.Println("[ERROR] Unknown in get_user() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
		}
	}

	return created, username, password, uniqueid, norows
}

func get_user_from_session(session string) (int, bool) {
	norows := false
	conn := get_db_connection()
	defer func(conn *sql.DB) {
		err := conn.Close()
		if err != nil {
			log.Println("[ERROR] Unknown in get_user_from_session() defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			norows = true
		}
	}(conn)
	var id int
	err := conn.QueryRow("SELECT id FROM sessions WHERE session = ? LIMIT 1", session).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			norows = true
		} else {
			log.Println("[ERROR] Unknown in get_user_from_session() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
		}
	}

	return id, norows
}

func check_username_taken(username string) (int, bool) {
	norows := false
	conn := get_db_connection()
	defer func(conn *sql.DB) {
		err := conn.Close()
		if err != nil {
			log.Println("[ERROR] Unknown in check_username_taken() defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			norows = true
		}
	}(conn)
	var id int
	err := conn.QueryRow("SELECT id FROM users WHERE lower(username) = ? LIMIT 1", username).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			norows = true
		} else {
			log.Println("[ERROR] Unknown in get_user() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
		}
	}

	return id, norows
}

func init_db() {
	if _, err := os.Stat("database.db"); os.IsNotExist(err) {
		if err := generateDB(); err != nil {
			log.Println("[ERROR] Unknown while generating database at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			return
		}
	} else {
		log.Print("Proceeding will overwrite the database. Proceed? (y/n) ")
		var answer string
		_, err := fmt.Scanln(&answer)
		if err != nil {
			log.Println("[ERROR] Unknown while scanning input at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			return
		}
		if answer == "y" || answer == "Y" {
			if err := generateDB(); err != nil {
				log.Println("[ERROR] Unknown while generating database at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				return
			}
		} else if answer == ":3" {
			log.Println("[:3] :3")
		} else {
			log.Println("[INFO] Stopped")
		}
	}
}

func generateDB() error {
	db, err := sql.Open("sqlite3", "database.db")
	if err != nil {
		return err
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {
			log.Println("[ERROR] Unknown in generateDB() defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			return
		}
	}(db)

	schemaBytes, err := os.ReadFile("schema.sql")
	if err != nil {
		return err
	}

	_, err = db.Exec(string(schemaBytes))
	if err != nil {
		return err
	}

	log.Println("[INFO] Generated database")
	return nil
}

func main() {
	if len(os.Args) > 1 {
		if os.Args[1] == "init_db" {
			init_db()
			os.Exit(0)
		}
	}

	if _, err := os.Stat("config.ini"); err == nil {
		log.Println("[INFO] Config loaded at", time.Now().Unix())
	} else if os.IsNotExist(err) {
		log.Println("[FATAL] config.ini does not exist")
		os.Exit(1)
	} else {
		log.Println("[FATAL] File is in quantumn uncertainty:", err)
		os.Exit(1)
	}

	viper.SetConfigName("config")
	viper.AddConfigPath("./")
	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		log.Println("[FATAL] Error in config file at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
		os.Exit(1)
	}

	HOST := viper.GetString("config.HOST")
	PORT := viper.GetInt("config.PORT")
	SECRET_KEY := viper.GetString("config.SECRET_KEY")
	PUBLIC_KEY_PATH := viper.GetString("config.PUBLIC_KEY")
	PRIVATE_KEY_PATH := viper.GetString("config.PRIVATE_KEY")

	if SECRET_KEY == "supersecretkey" {
		log.Println("[WARNING] Secret key not set. Please set the secret key to a non-default value.")
	}

	privateKey, err = os.ReadFile(PRIVATE_KEY_PATH)
	if err != nil {
		log.Fatal("[ERROR] Cannot read private key:", err)
	}

	publicKey, err = os.ReadFile(PUBLIC_KEY_PATH)
	if err != nil {
		log.Fatal("[ERROR] Cannot read public key:", err)
	}

	block, _ := pem.Decode(publicKey)
	if block == nil {
		log.Fatal("[ERROR] Failed to parse PEM block containing the public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal("[ERROR] Failed to parse public key:", err)
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		log.Fatal("[ERROR] Failed to convert public key to RSA public key")
	}

	modulus = rsaPubKey.N
	exponent = rsaPubKey.E

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	// Enable CORS
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "*")

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
			return
		}

		c.Next()
	})

	router.Static("/static", "./static")

	router.LoadHTMLGlob("templates/*.html")

	router.GET("/", func(c *gin.Context) {
		c.Redirect(302, "/login")
	})

	router.GET("/login", func(c *gin.Context) {
		c.HTML(200, "login.html", gin.H{})
	})

	router.GET("/signup", func(c *gin.Context) {
		c.HTML(200, "signup.html", gin.H{})
	})

	router.GET("/logout", func(c *gin.Context) {
		c.HTML(200, "logout.html", gin.H{})
	})

	router.GET("/app", func(c *gin.Context) {
		c.HTML(200, "main.html", gin.H{})
	})

	router.GET("/dashboard", func(c *gin.Context) {
		c.HTML(200, "dashboard.html", gin.H{})
	})

	router.GET("/aeskeyshare", func(c *gin.Context) {
		c.HTML(200, "aeskeyshare.html", gin.H{})
	})

	router.GET("/.well-known/openid-configuration", func(c *gin.Context) {
		c.HTML(200, "openid.html", gin.H{})
	})

	router.GET("/api/version", func(c *gin.Context) {
		c.String(200, "Burgerauth Version 1.3")
	})

	router.POST("/api/signup", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		username := data["username"].(string)
		password := data["password"].(string)

		if username == "" || password == "" || len(username) > 20 || !regexp.MustCompile("^[a-zA-Z0-9]+$").MatchString(username) {
			c.JSON(422, gin.H{"error": "Invalid username or password"})
			return
		}

		_, norows := check_username_taken(username)

		if !norows {
			c.JSON(409, gin.H{"error": "Username taken"})
			return
		}

		hashedPassword := hash(password, genSalt(16))

		conn := get_db_connection()
		defer func(conn *sql.DB) {
			err := conn.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/signup defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgerauth and refer to the docs for more detail. Include this error code: cannot_close_db.")
				return
			}
		}(conn)

		_, err = conn.Exec("INSERT INTO users (username, password, created, uniqueid) VALUES (?, ?, ?, ?)", username, hashedPassword, strconv.FormatInt(time.Now().Unix(), 10), genSalt(512))
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup user creation at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			return
		}
		log.Println("[INFO] Added new user at", time.Now().Unix())

		userid, _ := check_username_taken(username)

		randomchars := genSalt(512)

		_, err = conn.Exec("INSERT INTO sessions (session, id, device) VALUES (?, ?, ?)", randomchars, userid, c.Request.Header.Get("User-Agent"))
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup session creation at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			return
		}

		c.JSON(200, gin.H{"key": randomchars})
	})

	router.POST("/api/login", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		username := data["username"].(string)
		password := data["password"].(string)
		passwordchange := data["password"].(string)
		newpass := data["password"].(string)

		userid, norows := check_username_taken(username)

		if norows {
			c.JSON(401, gin.H{"error": "User does not exist"})
			return
		}

		_, _, userpassword, _, _ := get_user(userid)

		if !verifyHash(userpassword, password) {
			c.JSON(401, gin.H{"error": "Incorrect password"})
			return
		}

		randomchars := genSalt(512)

		conn := get_db_connection()
		defer func(conn *sql.DB) {
			err := conn.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/login defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgerauth and refer to the docs for more detail. Include this error code: cannot_close_db.")
				return
			}
		}(conn)

		_, err = conn.Exec("INSERT INTO sessions (session, id, device) VALUES (?, ?, ?)", randomchars, userid, c.Request.Header.Get("User-Agent"))
		if err != nil {
			log.Println("[ERROR] Unknown in /api/login session creation at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			return
		}

		if passwordchange == "yes" {
			hashpassword := hash(newpass, "")
			_, err = conn.Exec("UPDATE users SET password = ? WHERE username = ?", hashpassword, username)
			if err != nil {
				log.Println("[ERROR] Unknown in /api/login password change at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				return
			}
		}

		c.JSON(200, gin.H{"key": randomchars})
	})

	router.POST("/api/userinfo", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		secretkey := data["secretKey"].(string)

		userid, norows := get_user_from_session(secretkey)

		if norows {
			c.JSON(400, gin.H{"error": "Session does not exist"})
			return
		}

		created, username, _, _, norows := get_user(userid)

		if norows {
			c.JSON(400, gin.H{"error": "User does not exist"})
			return
		}

		c.JSON(200, gin.H{"username": username, "id": userid, "created": created})
	})

	router.GET("/userinfo", func(c *gin.Context) {
		token := strings.Fields(c.Request.Header["Authorization"][0])[1]

		conn := get_db_connection()
		defer func(conn *sql.DB) {
			err := conn.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /userinfo defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgerauth and refer to the docs for more detail. Include this error code: cannot_close_db.")
				return
			}
		}(conn)
		var blacklisted bool
		err := conn.QueryRow("SELECT blacklisted FROM blacklist WHERE openid = ? LIMIT 1", token).Scan(&blacklisted)
		if err == nil {
			c.JSON(400, gin.H{"error": "Token is in blacklist"})
			return
		} else {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /userinfo blacklist at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				return
			}
		}

		parsedtoken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})

		if err != nil {
			c.JSON(401, gin.H{"error": "Malformed token"})
			return
		}

		var claims jwt.MapClaims
		var ok bool

		if parsedtoken.Valid {
			claims, ok = parsedtoken.Claims.(jwt.MapClaims)
			if !ok {
				c.JSON(401, gin.H{"error": "Invalid token claims"})
				return
			}
		}

		session := claims["session"].(string)
		exp := claims["exp"].(float64)
		if int64(exp) < time.Now().Unix() {
			c.JSON(403, gin.H{"error": "Expired token"})
			return
		}

		userid, norows := get_user_from_session(session)
		if norows {
			c.JSON(400, gin.H{"error": "Session does not exist"})
			return
		}

		_, username, _, uniqueid, norows := get_user(userid)

		if norows {
			c.JSON(400, gin.H{"error": "User does not exist"})
			return
		}

		user := gin.H{"name": username}

		c.JSON(200, gin.H{"sub": uniqueid, "user": user})
	})

	router.POST("/api/uniqueid", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token := data["access_token"].(string)

		conn := get_db_connection()
		defer func(conn *sql.DB) {
			err := conn.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/uniqueid defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgerauth and refer to the docs for more detail. Include this error code: cannot_close_db.")
				return
			}
		}(conn)
		var blacklisted bool
		err = conn.QueryRow("SELECT blacklisted FROM blacklist WHERE token = ? LIMIT 1", token).Scan(&blacklisted)
		if err == nil {
			c.JSON(400, gin.H{"error": "Token is in blacklist"})
			return
		} else {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /api/uniqueid blacklist at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				return
			}
		}

		parsedtoken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})

		if err != nil {
			c.JSON(401, gin.H{"error": "Malformed token"})
			return
		}

		var claims jwt.MapClaims
		var ok bool

		if parsedtoken.Valid {
			claims, ok = parsedtoken.Claims.(jwt.MapClaims)
			if !ok {
				c.JSON(401, gin.H{"error": "Invalid token claims"})
				return
			}
		}

		session := claims["session"].(string)
		exp := claims["exp"].(float64)
		if int64(exp) < time.Now().Unix() {
			c.JSON(403, gin.H{"error": "Expired token"})
			return
		}

		userid, norows := get_user_from_session(session)
		if norows {
			c.JSON(400, gin.H{"error": "Session does not exist"})
			return
		}

		_, _, _, uniqueid, norows := get_user(userid)
		if norows {
			c.JSON(400, gin.H{"error": "User does not exist"})
			return
		}

		c.JSON(200, gin.H{"uniqueid": uniqueid})
	})

	router.POST("/api/loggedin", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token := data["access_token"].(string)
		conn := get_db_connection()
		defer func(conn *sql.DB) {
			err := conn.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/uniqueid defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgerauth and refer to the docs for more detail. Include this error code: cannot_close_db.")
				return
			}
		}(conn)
		var blacklisted bool
		err = conn.QueryRow("SELECT blacklisted FROM blacklist WHERE token = ? LIMIT 1", token).Scan(&blacklisted)
		if err == nil {
			c.JSON(400, gin.H{"error": "Token is in blacklist"})
			return
		} else {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /api/uniqueid blacklist at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				return
			}
		}

		parsedtoken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})

		if err != nil {
			c.JSON(401, gin.H{"error": "Malformed token"})
			return
		}

		var claims jwt.MapClaims
		var ok bool

		if parsedtoken.Valid {
			claims, ok = parsedtoken.Claims.(jwt.MapClaims)
			if !ok {
				c.JSON(401, gin.H{"error": "Invalid token claims"})
				return
			}
		}

		session := claims["session"].(string)
		exp := claims["exp"].(float64)
		if int64(exp) < time.Now().Unix() {
			c.JSON(403, gin.H{"error": "Expired token"})
			return
		}

		_, norows := get_user_from_session(session)
		if norows {
			c.JSON(400, gin.H{"error": "Session does not exist"})
			return
		}

		c.JSON(200, gin.H{"success": "true"})
	})

	router.GET("/api/auth", func(c *gin.Context) {
		secretKey, _ := c.Cookie("key")
		appId := c.Request.URL.Query().Get("client_id")
		code := c.Request.URL.Query().Get("code_challenge")
		codemethod := c.Request.URL.Query().Get("code_challenge_method")
		redirect_uri := c.Request.URL.Query().Get("redirect_uri")
		state := c.Request.URL.Query().Get("state")

		userid, norows := get_user_from_session(secretKey)

		if norows {
			c.String(400, "Session does not exist")
			return
		}

		_, username, _, _, norows := get_user(userid)

		if norows {
			c.String(400, "User does not exist")
			return
		}

		conn := get_db_connection()

		var appidcheck, rdiruricheck string

		err := conn.QueryRow("SELECT appId, rdiruri FROM oauth WHERE appId = ? LIMIT 1", appId).Scan(&appidcheck, &rdiruricheck)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.String(401, "OAuth screening failed")
			} else {
				log.Println("[ERROR] Unknown in /api/auth at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			}
			return
		}

		if !(rdiruricheck == redirect_uri) {
			c.String(401, "Redirect URI does not match")
			return
		}

		if !(appidcheck == appId) {
			c.String(401, "OAuth screening failed")
			return
		}

		datatemplate := jwt.MapClaims{
			"sub":       username,
			"iss":       "https://auth.hectabit.org",
			"name":      username,
			"aud":       appId,
			"exp":       time.Now().Unix() + 2592000,
			"iat":       time.Now().Unix(),
			"auth_time": time.Now().Unix(),
			"session":   secretKey,
			"nonce":     genSalt(512),
		}

		datatemplate2 := jwt.MapClaims{
			"exp":     time.Now().Unix() + 2592000,
			"iat":     time.Now().Unix(),
			"session": secretKey,
			"nonce":   genSalt(512),
		}

		jwt_token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, datatemplate).SignedString(privateKey)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/auth jwt_token at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgerauth and refer to the docs for more detail. Include this error code: jwt_token_cannotsign.")
			return
		}
		secret_token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, datatemplate2).SignedString(privateKey)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/auth secret_token at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgerauth and refer to the docs for more detail. Include this error code: jwt_token_cannotsign_secret.")
			return
		}

		randombytes := genSalt(512)

		_, err = conn.Exec("INSERT INTO logins (appId, secret, nextsecret, code, nextcode, creator, openid, nextopenid, pkce, pkcemethod) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", appId, randombytes, "none", secret_token, "none", userid, jwt_token, "none", code, codemethod)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/auth insert at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgerauth and refer to the docs for more detail. Include this error code: cannot_insert_auth.")
			return
		}

		if randombytes != "" {
			c.Redirect(302, redirect_uri+"?code="+randombytes+"&state="+state)
		} else {
			c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgerauth and refer to the docs for more detail. Include this error code: secretkey_not_found.")
			log.Println("[ERROR] Secretkey not found at", strconv.FormatInt(time.Now().Unix(), 10))
		}
	})

	router.POST("/api/tokenauth", func(c *gin.Context) {
		err := c.Request.ParseForm()
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid form data"})
			return
		}
		data := c.Request.Form

		appId := data.Get("client_id")
		code := data.Get("code")
		code_verify := data.Get("code_verifier")
		secret := data.Get("client_secret")

		var verifycode bool
		if code_verify == "" {
			verifycode = false
		} else {
			verifycode = true
		}

		conn := get_db_connection()
		defer func(conn *sql.DB) {
			err := conn.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/tokenauth defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgerauth and refer to the docs for more detail. Include this error code: cannot_close_db.")
				return
			}
		}(conn)

		var appidcheck, secretcheck, openid, logincode, pkce, pkcemethod string

		err = conn.QueryRow("SELECT o.appId, o.secret, l.openid, l.code, l.pkce, l.pkcemethod FROM oauth AS o JOIN logins AS l ON o.appId = l.appId WHERE o.appId = ? AND l.secret = ? LIMIT 1;", appId, code).Scan(&appidcheck, &secretcheck, &openid, &logincode, &pkce, &pkcemethod)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(401, gin.H{"error": "OAuth screening failed"})
			} else {
				log.Println("[ERROR] Unknown in /api/tokenauth at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			}
			return
		}
		if appidcheck != appId {
			c.JSON(401, gin.H{"error": "OAuth screening failed"})
			return
		}

		if verifycode {
			if pkce == "none" {
				c.JSON(400, gin.H{"error": "Attempted PKCE exchange with non-PKCE authentication"})
				return
			} else {
				if pkcemethod == "S256" {
					if sha256Base64(code_verify) != pkce {
						c.JSON(403, gin.H{"error": "Invalid PKCE code"})
						return
					}
				} else if pkcemethod == "plain" {
					if code_verify != pkce {
						c.JSON(403, gin.H{"error": "Invalid PKCE code"})
						return
					}
				} else {
					c.JSON(403, gin.H{"error": "Attempted PKCE exchange without supported PKCE token method"})
					return
				}
			}
		} else {
			if secret != secretcheck {
				c.JSON(401, gin.H{"error": "Invalid secret"})
				return
			}
		}

		_, err = conn.Exec("DELETE FROM logins WHERE code = ?", logincode)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/tokenauth delete at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			return
		}

		c.JSON(200, gin.H{"access_token": logincode, "token_type": "bearer", "expires_in": 2592000, "id_token": openid})
	})

	router.POST("/api/deleteauth", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		secretKey := data["secretKey"].(string)
		appId := data["appId"].(string)

		id, norows := get_user_from_session(secretKey)
		if norows {
			c.JSON(401, gin.H{"error": "User does not exist"})
			return
		}

		conn := get_db_connection()
		defer func(conn *sql.DB) {
			err := conn.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/deleteauth defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgerauth and refer to the docs for more detail. Include this error code: cannot_close_db.")
				return
			}
		}(conn)
		_, err = conn.Exec("DELETE FROM oauth WHERE appId = ? AND creator = ?", appId, id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(400, gin.H{"error": "AppID Not found"})
			} else {
				log.Println("[ERROR] Unknown in /api/deleteauth at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Unknown error occured"})
			}
		} else {
			c.JSON(200, gin.H{"success": "true"})
		}
	})

	router.POST("/api/newauth", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		secretKey := data["secretKey"].(string)
		appId := data["appId"].(string)
		rdiruri := data["rdiruri"].(string)

		id, norows := get_user_from_session(secretKey)
		if norows {
			c.JSON(400, gin.H{"error": "User does not exist"})
			return
		}

		var testsecret string
		secret := genSalt(512)
		conn := get_db_connection()
		defer func(conn *sql.DB) {
			err := conn.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/newauth defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgerauth and refer to the docs for more detail. Include this error code: cannot_close_db.")
				return
			}
		}(conn)

		for {
			err := conn.QueryRow("SELECT secret FROM oauth WHERE secret = ?", secret).Scan(&testsecret)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					break
				} else {
					log.Println("[ERROR] Unknown in /api/newauth secretselect at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
					c.JSON(500, gin.H{"error": "Unknown error occured"})
					return
				}
			} else {
				secret = genSalt(512)
			}
		}

		_, err = conn.Exec("SELECT secret FROM oauth WHERE appId = ?", appId)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				log.Println("[Info] New Oauth source added with ID:", appId)
			} else {
				log.Println("[ERROR] Unknown in /api/newauth at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Unknown error occured"})
				return
			}
		} else {
			secret = genSalt(512)
		}

		_, err = conn.Exec("INSERT INTO oauth (appId, creator, secret, rdiruri) VALUES (?, ?, ?, ?)", appId, id, secret, rdiruri)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/newauth insert at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			return
		}

		c.JSON(200, gin.H{"key": secret})
	})

	router.POST("/api/listauth", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		secretKey := data["secretKey"].(string)

		id, norows := get_user_from_session(secretKey)
		if norows {
			c.JSON(401, gin.H{"error": "User does not exist"})
			return
		}

		conn := get_db_connection()
		defer func(conn *sql.DB) {
			err := conn.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/listauth defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgerauth and refer to the docs for more detail. Include this error code: cannot_close_db.")
				return
			}
		}(conn)

		rows, err := conn.Query("SELECT appId FROM oauth WHERE creator = ? ORDER BY creator DESC", id)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to query database"})
			return
		}
		defer func(rows *sql.Rows) {
			err := rows.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/listauth rows close at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			}
		}(rows)

		var datatemplate []map[string]interface{}
		for rows.Next() {
			var appId string
			if err := rows.Scan(&appId); err != nil {
				c.JSON(500, gin.H{"error": "Failed to scan row"})
				return
			}
			template := map[string]interface{}{"appId": appId}
			datatemplate = append(datatemplate, template)
		}
		if err := rows.Err(); err != nil {
			c.JSON(500, gin.H{"error": "Error iterating over query results"})
			return
		}

		c.JSON(200, datatemplate)
	})

	router.POST("/api/deleteaccount", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		secretKey := data["secretKey"].(string)

		id, norows := get_user_from_session(secretKey)
		if norows {
			c.JSON(401, gin.H{"error": "User does not exist"})
			return
		}

		conn := get_db_connection()
		defer func(conn *sql.DB) {
			err := conn.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/deleteaccount defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgerauth and refer to the docs for more detail. Include this error code: cannot_close_db.")
				return
			}
		}(conn)

		_, err = conn.Exec("DELETE FROM userdata WHERE creator = ?", id)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /api/deleteuser userdata at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Unknown error occured"})
			}
		}

		_, err = conn.Exec("DELETE FROM logins WHERE creator = ?", id)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /api/deleteuser logins at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Unknown error occured"})
			}
		}

		_, err = conn.Exec("DELETE FROM oauth WHERE creator = ?", id)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /api/deleteuser oauth at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Unknown error occured"})
			}
		}

		_, err = conn.Exec("DELETE FROM users WHERE id = ?", id)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /api/deleteuser logins at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Unknown error occured"})
			}
		}

		c.JSON(200, gin.H{"success": "true"})
	})

	router.POST("/api/sessions/list", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		secretKey := data["secretKey"].(string)

		id, norows := get_user_from_session(secretKey)
		if norows {
			c.JSON(401, gin.H{"error": "User does not exist"})
			return
		}

		conn := get_db_connection()
		defer func(conn *sql.DB) {
			err := conn.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/sessions/list defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgerauth and refer to the docs for more detail. Include this error code: cannot_close_db.")
				return
			}
		}(conn)

		rows, err := conn.Query("SELECT sessionid, session, device FROM sessions WHERE id = ? ORDER BY id DESC", id)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /api/sessions/list at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Unknown error occured"})
			}
		}
		defer func(rows *sql.Rows) {
			err := rows.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/sessions/list rows close at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			}
		}(rows)

		var datatemplate []map[string]interface{}
		for rows.Next() {
			var id, sessionid, device string
			thisSession := false
			if err := rows.Scan(&id, &sessionid, &device); err != nil {
				c.JSON(500, gin.H{"error": "Failed to scan row"})
				return
			}
			if sessionid == secretKey {
				thisSession = true
			}
			template := map[string]interface{}{"id": sessionid, "thisSession": thisSession, "device": device}
			datatemplate = append(datatemplate, template)
		}
		if err := rows.Err(); err != nil {
			c.JSON(500, gin.H{"error": "Error iterating over query results"})
			return
		}

		c.JSON(200, datatemplate)
	})

	router.POST("/api/sessions/remove", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		secretKey := data["secretKey"].(string)
		sessionId := data["sessionId"].(string)

		id, norows := get_user_from_session(secretKey)
		if norows {
			c.JSON(401, gin.H{"error": "User does not exist"})
			return
		}

		conn := get_db_connection()
		defer func(conn *sql.DB) {
			err := conn.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/sessions/remove defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgerauth and refer to the docs for more detail. Include this error code: cannot_close_db.")
				return
			}
		}(conn)
		_, err = conn.Exec("DELETE FROM sessions WHERE sessionid = ? AND id = ?", sessionId, id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(422, gin.H{"error": "SessionID Not found"})
			} else {
				log.Println("[ERROR] Unknown in /api/sessions/remove at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Unknown error occured"})
			}
		} else {
			c.JSON(200, gin.H{"success": "true"})
		}
	})

	router.POST("/api/listusers", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		masterkey := data["masterkey"].(string)

		if masterkey == SECRET_KEY {
			conn := get_db_connection()
			defer func(conn *sql.DB) {
				err := conn.Close()
				if err != nil {
					log.Println("[ERROR] Unknown in /api/listusers defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
					c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgerauth and refer to the docs for more detail. Include this error code: cannot_close_db.")
					return
				}
			}(conn)

			rows, err := conn.Query("SELECT * FROM users ORDER BY id DESC")
			if err != nil {
				if !errors.Is(err, sql.ErrNoRows) {
					log.Println("[ERROR] Unknown in /api/listusers at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
					c.JSON(500, gin.H{"error": "Unknown error occured"})
				}
			}
			defer func(rows *sql.Rows) {
				err := rows.Close()
				if err != nil {
					log.Println("[ERROR] Unknown in /api/listusers rows close at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				}
			}(rows)

			var datatemplate []map[string]interface{}
			for rows.Next() {
				var id, username string
				if err := rows.Scan(&id, &username); err != nil {
					c.JSON(500, gin.H{"error": "Failed to scan row"})
					return
				}
				template := map[string]interface{}{"id": id, "username": username}
				datatemplate = append(datatemplate, template)
			}
			if err := rows.Err(); err != nil {
				c.JSON(500, gin.H{"error": "Error iterating over query results"})
				return
			}

			c.JSON(200, datatemplate)
		}
	})

	router.GET("/.well-known/jwks.json", func(c *gin.Context) {
		keys := gin.H{
			"keys": []gin.H{
				{
					"kty": "RSA",
					"alg": "RS256",
					"use": "sig",
					"kid": "burgerauth",
					"n":   modulus,
					"e":   exponent,
				},
			},
		}

		c.JSON(200, keys)
	})

	log.Println("[INFO] Server started at", time.Now().Unix())
	log.Println("[INFO] Welcome to Burgerauth! Today we are running on IP " + HOST + " on port " + strconv.Itoa(PORT) + ".")
	err = router.Run(HOST + ":" + strconv.Itoa(PORT))
	if err != nil {
		log.Println("[FATAL] Server failed to start at", time.Now().Unix(), err)
		return
	}
}
