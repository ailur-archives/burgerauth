// This code is licensed under the latest version of the GNU Affero General Public License

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"log"
	"math/big"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"concord.hectabit.org/HectaBit/captcha"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"golang.org/x/crypto/scrypt"
)

var (
	conn       *sql.DB
	mem        *sql.DB
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	modulus    *big.Int
	exponent   int
)

func Int64ToBase64URL(num int64) (string, error) {
	numBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(numBytes, uint64(num))
	startIndex := 0
	for startIndex < len(numBytes) && numBytes[startIndex] == 0 {
		startIndex++
	}
	trimmedBytes := numBytes[startIndex:]
	encoded := base64.URLEncoding.EncodeToString(trimmedBytes)
	return encoded, nil
}

func BigIntToBase64URL(num *big.Int) (string, error) {
	numBytes := num.Bytes()
	startIndex := 0
	for startIndex < len(numBytes) && numBytes[startIndex] == 0 {
		startIndex++
	}
	trimmedBytes := numBytes[startIndex:]
	encoded := base64.URLEncoding.EncodeToString(trimmedBytes)
	return encoded, nil
}

const saltChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func genSalt(length int) (string, error) {
	if length <= 0 {
		return "", errors.New("salt length must be greater than 0")
	}

	salt := make([]byte, length)
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	for i := range salt {
		salt[i] = saltChars[int(randomBytes[i])%len(saltChars)]
	}
	return string(salt), nil
}

func sha256Base64(s string) string {
	hashed := sha256.Sum256([]byte(s))
	encoded := base64.URLEncoding.EncodeToString(hashed[:])
	encoded = strings.TrimRight(encoded, "=")
	return encoded
}

func hash(password, salt string) (string, error) {
	passwordBytes := []byte(password)
	saltBytes := []byte(salt)

	derivedKey, err := scrypt.Key(passwordBytes, saltBytes, 32768, 8, 1, 64)
	if err != nil {
		return "", err
	}

	hashString := fmt.Sprintf("scrypt:32768:8:1$%s$%s", salt, hex.EncodeToString(derivedKey))
	return hashString, nil
}

func verifyHash(werkzeugHash, password string) (bool, error) {
	parts := strings.Split(werkzeugHash, "$")
	if len(parts) != 3 || parts[0] != "scrypt:32768:8:1" {
		return false, nil
	}
	salt := parts[1]
	computedHash, err := hash(password, salt)
	if err != nil {
		return false, err
	}

	return werkzeugHash == computedHash, nil
}

func getUser(id int) (string, string, string, string, error) {
	var created, username, password, uniqueId string
	err := conn.QueryRow("SELECT created, username, uniqueId, password FROM users WHERE id = ? LIMIT 1", id).Scan(&created, &username, &uniqueId, &password)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", "", "", sql.ErrNoRows
		} else {
			return "", "", "", "", err
		}
	}

	return created, username, password, uniqueId, nil
}

func getSession(session string) (int, int, error) {
	var id, sessionId int
	err := conn.QueryRow("SELECT sessionid, id FROM sessions WHERE session = ? LIMIT 1", session).Scan(&sessionId, &id)
	if err != nil {
		return 0, 0, err
	}
	return sessionId, id, nil
}

func checkUsernameTaken(username string) (int, bool, error) {
	var id int
	err := conn.QueryRow("SELECT id FROM users WHERE lower(username) = ? LIMIT 1", username).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, false, nil
		} else {
			return 0, true, err
		}
	}

	return id, true, nil
}

func initDb() {
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
	if _, err := os.Stat("config.ini"); err == nil {
		log.Println("[INFO] Config loaded at", time.Now().Unix())
	} else if os.IsNotExist(err) {
		log.Println("[FATAL] config.ini does not exist")
		os.Exit(1)
	} else {
		log.Println("[FATAL] File is in quantum uncertainty:", err)
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

	Host := viper.GetString("config.HOST")
	Port := viper.GetInt("config.PORT")
	privacyPolicy := viper.GetString("config.PRIVACY_POLICY")
	hostName := viper.GetString("config.URL")
	identifier := viper.GetString("config.IDENTIFIER")
	keyid := viper.GetString("config.KEY_ID")
	SecretKey := viper.GetString("config.SECRET_KEY")
	PublicKeyPath := viper.GetString("config.PUBLIC_KEY")
	PrivateKeyPath := viper.GetString("config.PRIVATE_KEY")

	if SecretKey == "supersecretkey" {
		log.Println("[WARNING] Secret key not set. Please set the secret key to a non-default value.")
	}

	conn, err = sql.Open("sqlite3", "database.db")
	if err != nil {
		log.Fatalln("[FATAL] Cannot open database at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
	}
	defer func(conn *sql.DB) {
		err := conn.Close()
		if err != nil {
			log.Println("[ERROR] Unknown in main() defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
		}
	}(conn)

	if len(os.Args) > 1 {
		if os.Args[1] == "init_db" {
			initDb()
			os.Exit(0)
		}
	}

	mem, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Fatalln("[FATAL] Cannot open memory database at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
	}
	defer func(mem *sql.DB) {
		err := mem.Close()
		if err != nil {
			log.Println("[ERROR] Unknown in main() memory defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
		}
	}(mem)

	_, err = mem.Exec("CREATE TABLE logins (appId TEXT NOT NULL, exchangeCode TEXT NOT NULL, loginToken TEXT NOT NULL, creator INT NOT NULL UNIQUE, openid TEXT NOT NULL, pkce TEXT NOT NULL DEFAULT 'none', pkcemethod TEXT NOT NULL DEFAULT 'none')")
	if err != nil {
		log.Fatalln("[FATAL] Cannot create logins table at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
	}

	privateKeyFile, err := os.ReadFile(PrivateKeyPath)
	if err != nil {
		log.Fatal("[ERROR] Cannot read private key:", err)
	}

	block, _ := pem.Decode(privateKeyFile)
	if block == nil {
		log.Fatal("[ERROR] Failed to parse PEM block containing the private key")
	}

	privateKeyRaw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal("[ERROR] Failed to parse private key:", err)
	}

	var ok bool
	privateKey, ok = privateKeyRaw.(*rsa.PrivateKey)
	if !ok {
		log.Fatal("[ERROR] Failed to convert private key to RSA private key")
	}

	pubKeyFile, err := os.ReadFile(PublicKeyPath)
	if err != nil {
		log.Fatal("[ERROR] Cannot read public key:", err)
	}

	block, _ = pem.Decode(pubKeyFile)
	if block == nil {
		log.Fatal("[ERROR] Failed to parse PEM block containing the public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal("[ERROR] Failed to parse public key:", err)
	}

	publicKey, ok = pubKey.(*rsa.PublicKey)
	if !ok {
		log.Fatal("[ERROR] Failed to convert public key to RSA public key")
	}

	modulus = privateKey.N
	exponent = privateKey.E

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	store := cookie.NewStore([]byte(SecretKey))
	router.Use(sessions.Sessions("currentSession", store))

	// Enable CORS
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "*, Authorization")
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
		c.HTML(200, "login.html", gin.H{"privacy": privacyPolicy, "identifier": identifier})
	})

	router.GET("/signup", func(c *gin.Context) {
		session := sessions.Default(c)
		sessionId, err := genSalt(512)
		if err != nil {
			fmt.Println("[ERROR] Failed to generate session token at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-SIGNUP-SESSION-GEN")
			return
		}
		session.Options(sessions.Options{
			SameSite: 3,
		})
		data, err := captcha.New(500, 100)
		if err != nil {
			fmt.Println("[ERROR] Failed to generate captcha at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Failed to generate captcha")
			return
		}
		session.Set("captcha", data.Text)
		session.Set("unique_token", sessionId)
		err = session.Save()
		if err != nil {
			fmt.Println("[ERROR] Failed to save session in /login at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Failed to save session")
			return
		}
		var b64bytes bytes.Buffer
		err = data.WriteImage(&b64bytes)
		if err != nil {
			fmt.Println("[ERROR] Failed to encode captcha at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Failed to encode captcha")
			return
		}
		c.HTML(200, "signup.html", gin.H{
			"captcha_image": base64.StdEncoding.EncodeToString(b64bytes.Bytes()),
			"unique_token":  sessionId,
			"privacy":       privacyPolicy,
			"identifier":    identifier,
		})
	})

	router.GET("/logout", func(c *gin.Context) {
		c.HTML(200, "logout.html", gin.H{"identifier": identifier})
	})

	router.GET("/app", func(c *gin.Context) {
		name := ""
		if c.Request.URL.Query().Get("client_id") != "" {
			appId := c.Request.URL.Query().Get("client_id")
			err := conn.QueryRow("SELECT name FROM oauth WHERE appId = ? LIMIT 1", appId).Scan(&name)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					c.String(404, "App not found")
				} else {
					log.Println("[ERROR] Unknown in /app at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				}
				return
			}
		}
		c.HTML(200, "main.html", gin.H{"name": name, "identifier": identifier})
	})

	router.GET("/dashboard", func(c *gin.Context) {
		c.HTML(200, "dashboard.html", gin.H{"identifier": identifier})
	})

	router.GET("/account", func(c *gin.Context) {
		c.HTML(200, "acct.html", gin.H{"identifier": identifier})
	})

	router.GET("/aeskeyshare", func(c *gin.Context) {
		c.HTML(200, "aeskeyshare.html", gin.H{"identifier": identifier})
	})

	router.GET("/privacy", func(c *gin.Context) {
		c.Redirect(301, privacyPolicy)
	})

	router.GET("/.well-known/openid-configuration", func(c *gin.Context) {
		c.HTML(200, "openid.html", gin.H{"hostName": hostName})
	})

	router.GET("/api/version", func(c *gin.Context) {
		c.String(200, "Burgerauth Version 1.3")
	})

	router.GET("/api/servicename", func(c *gin.Context) {
		c.JSON(200, gin.H{"name": identifier})
	})

	router.POST("/api/signup", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		session := sessions.Default(c)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		username, ok := data["username"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		password, ok := data["password"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		if data["unique_token"].(string) != session.Get("unique_token") {
			log.Println("yes, it's this error")
			log.Println(session.Get("unique_token"), data["unique_token"])
			c.JSON(403, gin.H{"error": "Invalid token"})
			return
		}
		if data["captcha"].(string) != session.Get("captcha") {
			c.JSON(401, gin.H{"error": "Captcha failed"})
			return
		}

		if username == "" || password == "" || len(username) > 20 || !regexp.MustCompile("^[a-zA-Z0-9]+$").MatchString(username) {
			c.JSON(422, gin.H{"error": "Invalid username or password"})
			return
		}

		_, taken, err := checkUsernameTaken(username)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup checkUsernameTaken() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-SIGNUP-CHECKUSERNAME"})
			return
		}
		if taken {
			c.JSON(409, gin.H{"error": "Username taken"})
			return
		}

		salt, err := genSalt(16)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup genSalt() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-SIGNUP-SALT"})
			return
		}
		hashedPassword, err := hash(password, salt)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup hash() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-SIGNUP-HASH"})
			return
		}

		sub, err := genSalt(255)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup genSalt() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-SIGNUP-SUB"})
			return
		}
		_, err = conn.Exec("INSERT INTO users (username, password, created, uniqueid) VALUES (?, ?, ?, ?)", username, hashedPassword, strconv.FormatInt(time.Now().Unix(), 10), sub)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup user creation at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			return
		}
		log.Println("[INFO] Added new user at", time.Now().Unix())

		userid, _, err := checkUsernameTaken(username)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup checkUsernameTaken() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-SIGNUP-CHECKUSERNAME"})
			return
		}

		randomChars, err := genSalt(512)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup token genSalt() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-SIGNUP-SESSIONSALT"})
			return
		}

		_, err = conn.Exec("INSERT INTO sessions (session, id, device) VALUES (?, ?, ?)", randomChars, userid, c.Request.Header.Get("User-Agent"))
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup session Exec() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-SIGNUP-SESSIONINSERT"})
			return
		}

		c.JSON(200, gin.H{"key": randomChars})
	})

	router.POST("/api/login", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		username, ok := data["username"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		password, ok := data["password"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		passwordChange, ok := data["password"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		newPass, ok := data["password"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		userid, taken, err := checkUsernameTaken(username)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/login checkUsernameTaken() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LOGIN-CHECKUSERNAME"})
			return
		}
		if !taken {
			c.JSON(401, gin.H{"error": "User does not exist"})
			return
		}

		_, _, userPassword, _, err := getUser(userid)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/login getUser() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LOGIN-GETUSER"})
			return
		}

		passwordCheck, err := verifyHash(userPassword, password)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/login password check at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LOGIN-PASSWORDCHECK"})
			return
		}
		if !passwordCheck {
			c.JSON(401, gin.H{"error": "Incorrect password"})
			return
		}

		randomChars, err := genSalt(512)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/login token genSalt() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LOGIN-SESSIONSALT"})
			return
		}

		_, err = conn.Exec("INSERT INTO sessions (session, id, device) VALUES (?, ?, ?)", randomChars, userid, c.Request.Header.Get("User-Agent"))
		if err != nil {
			log.Println("[ERROR] Unknown in /api/login session creation at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LOGIN-SESSIONINSERT"})
			return
		}

		if passwordChange == "yes" {
			hashPassword, err := hash(newPass, "")
			if err != nil {
				log.Println("[ERROR] Unknown in /api/login password hash at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LOGIN-PASSWORDHASH"})
				return
			}
			_, err = conn.Exec("UPDATE users SET password = ? WHERE username = ?", hashPassword, username)
			if err != nil {
				log.Println("[ERROR] Unknown in /api/login password change at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LOGIN-PASSWORDCHANGE"})
				return
			}
		}

		c.JSON(200, gin.H{"key": randomChars})
	})

	router.POST("/api/userinfo", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		secretKey, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		_, userid, err := getSession(secretKey)
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		created, username, _, _, err := getUser(userid)
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(400, gin.H{"error": "User does not exist"})
			return
		} else if err != nil {
			log.Println("[ERROR] Unknown in /api/userinfo getUser() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-USERINFO-GETUSER"})
			return
		}

		c.JSON(200, gin.H{"username": username, "id": userid, "created": created})
	})

	router.GET("/userinfo", func(c *gin.Context) {
		var token string
		if len(c.Request.Header["Authorization"]) > 0 {
			if len(strings.Fields(c.Request.Header["Authorization"][0])) > 1 {
				token = strings.Fields(c.Request.Header["Authorization"][0])[1]
			} else {
				c.JSON(400, gin.H{"error": "Invalid token"})
				return
			}
		} else {
			c.JSON(400, gin.H{"error": "Invalid token"})
			return
		}

		var blacklisted bool
		err := conn.QueryRow("SELECT blacklisted FROM blacklist WHERE openid = ? LIMIT 1", token).Scan(&blacklisted)
		if err == nil {
			c.JSON(400, gin.H{"error": "Token is in blacklist"})
			return
		} else {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /userinfo blacklist at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-USERINFO-BLACKLIST"})
				return
			}
		}

		parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})

		if err != nil {
			c.JSON(401, gin.H{"error": "Malformed token"})
			return
		}

		var claims jwt.MapClaims
		var ok bool

		if parsedToken.Valid {
			claims, ok = parsedToken.Claims.(jwt.MapClaims)
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

		_, userid, err := getSession(session)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		_, username, _, sub, err := getUser(userid)
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(400, gin.H{"error": "User does not exist"})
			return
		} else if err != nil {
			log.Println("[ERROR] Unknown in /userinfo getUser() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-USERINFO-GETUSER"})
			return
		}

		c.JSON(200, gin.H{"sub": sub[:255], "name": username})
	})

	router.POST("/api/uniqueid", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token, ok := data["access_token"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		var blacklisted bool
		err = conn.QueryRow("SELECT blacklisted FROM blacklist WHERE token = ? LIMIT 1", token).Scan(&blacklisted)
		if err == nil {
			c.JSON(400, gin.H{"error": "Token is in blacklist"})
			return
		} else {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /api/sub blacklist at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-UNIQUEID-BLACKLIST"})
				return
			}
		}

		parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})

		if err != nil {
			c.JSON(401, gin.H{"error": "Malformed token"})
			return
		}

		var claims jwt.MapClaims
		if parsedToken.Valid {
			claims, ok = parsedToken.Claims.(jwt.MapClaims)
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

		_, userid, err := getSession(session)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		_, _, _, sub, err := getUser(userid)
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(400, gin.H{"error": "User does not exist"})
			return
		} else if err != nil {
			log.Println("[ERROR] Unknown in /api/userinfo getUser() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-UNIQUEID-GETUSER"})
			return
		}

		c.JSON(200, gin.H{"sub": sub})
	})

	router.POST("/api/loggedin", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token, ok := data["access_token"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		var blacklisted bool
		err = conn.QueryRow("SELECT blacklisted FROM blacklist WHERE token = ? LIMIT 1", token).Scan(&blacklisted)
		if err == nil {
			c.JSON(400, gin.H{"error": "Token is in blacklist"})
			return
		} else {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /api/loggedin blacklist at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LOGGEDIN-BLACKLIST"})
				return
			}
		}

		parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})

		if err != nil {
			c.JSON(401, gin.H{"error": "Malformed token"})
			return
		}

		var claims jwt.MapClaims
		if parsedToken.Valid {
			claims, ok = parsedToken.Claims.(jwt.MapClaims)
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

		_, _, err = getSession(session)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		c.JSON(200, gin.H{"appId": claims["aud"]})
	})

	router.GET("/api/auth", func(c *gin.Context) {
		secretKey, _ := c.Cookie("key")
		appId := c.Request.URL.Query().Get("client_id")
		code := c.Request.URL.Query().Get("code_challenge")
		codeMethod := c.Request.URL.Query().Get("code_challenge_method")
		redirectUri := c.Request.URL.Query().Get("redirect_uri")
		state := c.Request.URL.Query().Get("state")
		nonce := c.Request.URL.Query().Get("nonce")
		deny := c.Request.URL.Query().Get("deny")

		var appIdCheck, redirectUriCheck string

		err := conn.QueryRow("SELECT appId, rdiruri FROM oauth WHERE appId = ? LIMIT 1", appId).Scan(&appIdCheck, &redirectUriCheck)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				fmt.Println(appId)
				c.String(401, "OAuth screening failed")
			} else {
				log.Println("[ERROR] Unknown in /api/auth at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-AUTH-SELECT")
			}
			return
		}

		if !(redirectUriCheck == redirectUri) {
			c.String(401, "Redirect URI does not match")
			return
		}

		if deny == "true" {
			c.Redirect(302, redirectUri+"?error=access_denied&state="+state)
			return
		}

		if !(appIdCheck == appId) {
			fmt.Println(appIdCheck, appId)
			c.String(401, "OAuth screening failed")
			return
		}

		if nonce == "none" {
			nonce, err = genSalt(512)
			if err != nil {
				log.Println("[ERROR] Unknown in /api/auth nonce genSalt() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-AUTH-NONCE")
				return
			}
		}

		_, userid, err := getSession(secretKey)
		if err != nil {
			c.String(401, "Invalid session")
			return
		}

		_, username, _, sub, err := getUser(userid)
		if errors.Is(err, sql.ErrNoRows) {
			c.String(400, "User does not exist")
			return
		} else if err != nil {
			log.Println("[ERROR] Unknown in /api/userinfo getUser() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-AUTH-GETUSER")
			return
		}

		dataTemplate := jwt.MapClaims{
			"sub":       sub[:255],
			"iss":       hostName,
			"name":      username,
			"aud":       appId,
			"exp":       time.Now().Unix() + 2592000,
			"iat":       time.Now().Unix(),
			"auth_time": time.Now().Unix(),
			"session":   secretKey,
			"nonce":     nonce,
		}

		secondNonce, err := genSalt(512)
		dataTemplateTwo := jwt.MapClaims{
			"exp":     time.Now().Unix() + 2592000,
			"iat":     time.Now().Unix(),
			"session": secretKey,
			"nonce":   secondNonce,
		}

		tokenTemp := jwt.NewWithClaims(jwt.SigningMethodRS256, dataTemplate)
		tokenTemp.Header["kid"] = "burgerauth"
		jwtToken, err := tokenTemp.SignedString(privateKey)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/auth jwt_token at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-AUTH-JWTCANNOTSIGN")
			return
		}

		secretTemp := jwt.NewWithClaims(jwt.SigningMethodRS256, dataTemplateTwo)
		secretTemp.Header["kid"] = "burgerauth"
		secretToken, err := secretTemp.SignedString(privateKey)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/auth secret_token at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-AUTH-JWTCANNOTSIGN.")
			return
		}

		randomBytes, err := genSalt(512)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/auth randomBytes at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-AUTH-RANDOMBYTES.")
			return
		}

		_, err = mem.Exec("DELETE FROM logins WHERE creator = ?", userid)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/auth delete at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-AUTH-DELETE.")
			return
		}

		_, err = mem.Exec("INSERT INTO logins (appId, exchangeCode, loginToken, creator, openid, pkce, pkcemethod) VALUES (?, ?, ?, ?, ?, ?, ?)", appId, randomBytes, secretToken, userid, jwtToken, code, codeMethod)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/auth insert at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-AUTH-INSERT.")
			return
		}

		if randomBytes != "" {
			c.Redirect(302, redirectUri+"?code="+randomBytes+"&state="+state)
		} else {
			c.String(500, "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-AUTH-REDIRECT.")
			log.Println("[ERROR] Secret key not found at", strconv.FormatInt(time.Now().Unix(), 10))
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
		codeVerify := data.Get("code_verifier")
		secret := data.Get("client_secret")

		var verifyCode bool
		if codeVerify == "" {
			verifyCode = false
		} else {
			verifyCode = true
		}

		var appIdCheck, secretCheck, openid, loginCode, PKCECode, PKCEMethod string

		err = conn.QueryRow("SELECT appId, secret FROM oauth WHERE appId = ?;", appId).Scan(&appIdCheck, &secretCheck)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(401, gin.H{"error": "OAuth screening failed"})
			} else {
				log.Println("[ERROR] Unknown in /api/tokenauth at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-TOKENAUTH-SELECT"})
			}
			return
		}

		err = mem.QueryRow("SELECT loginToken, openid, pkce, pkcemethod FROM logins WHERE exchangeCode = ?", code).Scan(&loginCode, &openid, &PKCECode, &PKCEMethod)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(401, gin.H{"error": "OAuth screening failed"})
			} else {
				log.Println("[ERROR] Unknown in /api/tokenauth memory query at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-TOKENAUTH-MEMSELECT"})
			}
			return
		}
		if appIdCheck != appId {
			c.JSON(401, gin.H{"error": "OAuth screening failed"})
			return
		}

		if verifyCode {
			if PKCECode == "none" {
				c.JSON(400, gin.H{"error": "Attempted PKCECode exchange with non-PKCECode authentication"})
				return
			} else {
				if PKCEMethod == "S256" {
					if sha256Base64(codeVerify) != PKCECode {
						c.JSON(403, gin.H{"error": "Invalid PKCECode code"})
						return
					}
				} else if PKCEMethod == "plain" {
					if codeVerify != PKCECode {
						c.JSON(403, gin.H{"error": "Invalid PKCECode code"})
						return
					}
				} else {
					c.JSON(403, gin.H{"error": "Attempted PKCECode exchange without supported PKCECode token method"})
					return
				}
			}
		} else {
			if secret != secretCheck {
				c.JSON(401, gin.H{"error": "Invalid secret"})
				return
			}
		}

		_, err = mem.Exec("DELETE FROM logins WHERE loginToken = ?", loginCode)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/tokenauth delete at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-TOKENAUTH-DELETE"})
			return
		}

		c.JSON(200, gin.H{"access_token": loginCode, "token_type": "bearer", "expires_in": 2592000, "id_token": openid})
	})

	router.POST("/api/deleteauth", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		secretKey, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		appId, ok := data["appId"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		_, id, err := getSession(secretKey)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		_, err = conn.Exec("DELETE FROM oauth WHERE appId = ? AND creator = ?", appId, id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(400, gin.H{"error": "AppID Not found"})
			} else {
				log.Println("[ERROR] Unknown in /api/deleteauth at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-DELETEAUTH-DELETE"})
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

		secretKey, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		name, ok := data["name"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		redirectUri, ok := data["redirectUri"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		_, id, err := getSession(secretKey)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		var testsecret, testappid string
		secret, err := genSalt(512)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/newauth secretgen at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-NEWAUTH-SECRETGEN"})
			return
		}
		for {
			err := conn.QueryRow("SELECT secret FROM oauth WHERE secret = ?", secret).Scan(&testsecret)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					break
				} else {
					log.Println("[ERROR] Unknown in /api/newauth secretselect at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-NEWAUTH-SECRETSELECT"})
					return
				}
			} else {
				secret, err = genSalt(512)
				if err != nil {
					log.Println("[ERROR] Unknown in /api/newauth secretgen at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-NEWAUTH-SECRETGEN"})
					return
				}
			}
		}

		appId, err := genSalt(32)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/newauth appidgen at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-NEWAUTH-APPIDGEN"})
			return
		}

		for {
			err = conn.QueryRow("SELECT appId FROM oauth WHERE appId = ?", appId).Scan(&testappid)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					log.Println("[Info] New Oauth source added with ID:", appId)
					break
				} else {
					log.Println("[ERROR] Unknown in /api/newauth appidcheck at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-NEWAUTH-APPIDCHECK"})
					return
				}
			} else {
				appId, err = genSalt(32)
				if err != nil {
					log.Println("[ERROR] Unknown in /api/newauth appidgen at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-NEWAUTH-LAPPIDGEN"})
					return
				}
			}
		}

		_, err = conn.Exec("INSERT INTO oauth (name, appId, creator, secret, redirectUri) VALUES (?, ?, ?, ?, ?)", name, appId, id, secret, redirectUri)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/newauth insert at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-NEWAUTH-INSERT"})
			return
		}

		c.JSON(200, gin.H{"key": secret, "appId": appId})
	})

	router.POST("/api/listauth", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		secretKey, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		_, id, err := getSession(secretKey)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		rows, err := conn.Query("SELECT appId, name, rdiruri FROM oauth WHERE creator = ? ORDER BY creator DESC", id)
		if err != nil {
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LISTAUTH-QUERY"})
			return
		}
		defer func(rows *sql.Rows) {
			err := rows.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/listauth rows close at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LISTAUTH-ROWSCLOSE"})
				return
			}
		}(rows)

		var dataTemplate []map[string]interface{}
		for rows.Next() {
			var appId, name, redirectUri string
			if err := rows.Scan(&appId, &name, &redirectUri); err != nil {
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LISTAUTH-SCAN"})
				return
			}
			template := map[string]interface{}{"appId": appId, "name": name, "redirectUri": redirectUri}
			dataTemplate = append(dataTemplate, template)
		}
		if err := rows.Err(); err != nil {
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LISTAUTH-ROWSERR"})
			return
		}

		c.JSON(200, dataTemplate)
	})

	router.POST("/api/deleteaccount", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		secretKey, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		_, id, err := getSession(secretKey)
		if err != nil {
			c.JSON(401, gin.H{"error": "Session does not exist"})
			return
		}

		_, err = conn.Exec("DELETE FROM userdata WHERE creator = ?", id)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /api/deleteaccount userdata at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-DELETEACCT-USERDATA"})
				return
			}
		}

		_, err = mem.Exec("DELETE FROM logins WHERE creator = ?", id)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /api/deleteaccount logins at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-DELETEACCT-LOGINS"})
				return
			}
		}

		_, err = conn.Exec("DELETE FROM oauth WHERE creator = ?", id)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /api/deleteuser oauth at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-DELETEUSER-OAUTH"})
				return
			}
		}

		_, err = conn.Exec("DELETE FROM users WHERE id = ?", id)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /api/deleteuser logins at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-DELETEUSER-USERS"})
				return
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

		secretKey, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		_, id, err := getSession(secretKey)
		if err != nil {
			c.JSON(401, gin.H{"error": "Session does not exist"})
			return
		}

		rows, err := conn.Query("SELECT sessionid, session, device FROM sessions WHERE id = ? ORDER BY id DESC", id)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /api/sessions/list at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-SESSIONS-LIST"})
				return
			}
		}
		defer func(rows *sql.Rows) {
			err := rows.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/sessions/list rows close at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-SESSIONS-LIST-ROWSCLOSE"})
				return
			}
		}(rows)

		var dataTemplate []map[string]interface{}
		for rows.Next() {
			var id, sessionId, device string
			thisSession := false
			if err := rows.Scan(&id, &sessionId, &device); err != nil {
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-SESSIONS-LIST-SCAN"})
				return
			}
			if sessionId == secretKey {
				thisSession = true
			}
			template := map[string]interface{}{"id": sessionId, "thisSession": thisSession, "device": device}
			dataTemplate = append(dataTemplate, template)
		}
		if err := rows.Err(); err != nil {
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-SESSIONS-LIST-ERR"})
			return
		}

		c.JSON(200, dataTemplate)
	})

	router.POST("/api/sessions/remove", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		secretKey, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		sessionId, ok := data["sessionId"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		_, id, err := getSession(secretKey)
		if err != nil {
			c.JSON(401, gin.H{"error": "Session does not exist"})
			return
		}

		_, err = conn.Exec("DELETE FROM sessions WHERE sessionid = ? AND id = ?", sessionId, id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(422, gin.H{"error": "SessionID Not found"})
			} else {
				log.Println("[ERROR] Unknown in /api/sessions/remove at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-SESSIONS-REMOVE"})
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

		masterKey, ok := data["masterKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		if masterKey == SecretKey {
			rows, err := conn.Query("SELECT * FROM users ORDER BY id DESC")
			if err != nil {
				if !errors.Is(err, sql.ErrNoRows) {
					log.Println("[ERROR] Unknown in /api/listusers at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LISTUSERS-QUERY"})
					return
				}
			}
			defer func(rows *sql.Rows) {
				err := rows.Close()
				if err != nil {
					log.Println("[ERROR] Unknown in /api/listusers rows close at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LISTUSERS-ROWSCLOSE"})
					return
				}
			}(rows)

			var datatemplate []map[string]interface{}
			for rows.Next() {
				var id, username string
				if err := rows.Scan(&id, &username); err != nil {
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LISTUSERS-SCAN"})
					return
				}
				template := map[string]interface{}{"id": id, "username": username}
				datatemplate = append(datatemplate, template)
			}
			if err := rows.Err(); err != nil {
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LISTUSERS-ERR"})
				return
			}

			c.JSON(200, datatemplate)
		}
	})

	router.GET("/.well-known/jwks.json", func(c *gin.Context) {
		mod, err := BigIntToBase64URL(modulus)
		if err != nil {
			log.Println("[ERROR] Unknown in /well-known/jwks.json modulus at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-JWKS-MODULUS"})
			return
		}

		exp, err := Int64ToBase64URL(int64(exponent))
		if err != nil {
			log.Println("[ERROR] Unknown in /well-known/jwks.json exponent at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-JWKS-EXPONENT"})
			return
		}
		keys := gin.H{
			"keys": []gin.H{
				{
					"kty": "RSA",
					"alg": "RS256",
					"use": "sig",
					"kid": keyid,
					"n":   mod,
					"e":   exp,
				},
			},
		}

		c.JSON(200, keys)
	})

	log.Println("[INFO] Server started at", time.Now().Unix())
	log.Println("[INFO] Welcome to Burgerauth! Today we are running on IP " + Host + " on port " + strconv.Itoa(Port) + ".")
	err = router.Run(Host + ":" + strconv.Itoa(Port))
	if err != nil {
		log.Fatalln("[FATAL] Server failed to begin operations at", time.Now().Unix(), err)
	}
}
