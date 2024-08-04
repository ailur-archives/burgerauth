// This code is licensed under the latest version of the GNU Affero General Public License

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/catalinc/hashcash"
	"github.com/golang-jwt/jwt"
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

func ensureTrailingSlash(url string) string {
	if !strings.HasSuffix(url, "/") {
		return url + "/"
	}
	return url
}

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

func randomChars(length int) (string, error) {
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
	err := mem.QueryRow("SELECT sessionid, id FROM sessions WHERE session = ? LIMIT 1", session).Scan(&sessionId, &id)
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
			log.Println("[ERROR] Unknown while generating database:", err)
			return
		}
	} else {
		log.Print("Proceeding will overwrite the database. Proceed? (y/n) ")
		var answer string
		_, err := fmt.Scanln(&answer)
		if err != nil {
			log.Println("[ERROR] Unknown while scanning input:", err)
			return
		}
		if answer == "y" || answer == "Y" {
			if err := generateDB(); err != nil {
				log.Println("[ERROR] Unknown while generating database:", err)
				return
			}
		} else if answer == ":3" {
			log.Println("[:3] :3")
		} else {
			log.Println("[INFO] Stopped")
		}
	}
}

func migrateDb() {
	_, err := os.Stat("database.db")
	if os.IsNotExist(err) {
		err = generateDB()
		if err != nil {
			log.Fatalln("[FATAL] Unknown while generating database:", err)
		}
	} else {
		log.Println("[PROMPT] Proceeding will render the database unusable for older versions of Burgerauth. Proceed? (y/n): ")
		var answer string
		_, err := fmt.Scanln(&answer)
		if err != nil {
			log.Fatalln("[FATAL] Unknown while scanning input:", err)
		}
		if strings.ToLower(answer) == "y" {
			_, err = conn.Exec("DROP TABLE sessions")
			if err != nil {
				log.Println("[WARN] Unknown while migrating database (1/4):", err)
				log.Println("[INFO] This is likely because your database is already migrated. This is not a problem, and Burgerauth does not need this removed - it is just for cleanup")
			}
			_, err = conn.Exec("ALTER TABLE users ADD COLUMN migrated INTEGER NOT NULL DEFAULT 0")
			if err != nil {
				log.Println("[WARN] Unknown while migrating database (2/4):", err)
				log.Println("[INFO] This is likely because your database is already migrated. This is not a problem, but if it is not, it may cause issues with migrating to Burgerauth's newer hashing algorithm")
			}
			_, err = conn.Exec("ALTER TABLE oauth ADD COLUMN scopes TEXT NOT NULL DEFAULT '[\"openid\"]'")
			if err != nil {
				log.Println("[WARN] Unknown while migrating database (3/4):", err)
				log.Println("[INFO] This is likely because your database is already migrated. This is not a problem, but if it is not, it may cause issues with migrating from beta versions of Burgerauth")
			}
			_, err = conn.Exec("ALTER TABLE oauth ADD COLUMN keyShareUri TEXT NOT NULL DEFAULT 'none'")
			if err != nil {
				log.Println("[WARN] Unknown while migrating database (4/4):", err)
				log.Println("[INFO] This is likely because your database is already migrated. This is not a problem, but if it is not, it may cause issues with migrating from beta versions of Burgerauth")
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
			log.Println("[ERROR] Unknown in generateDB() defer:", err)
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

	log.Println("[INFO] Generated database!")
	return nil
}

func createTestApp(hostName string) error {
	log.Println("[INFO] Creating test app...")
	_, err := conn.Exec("INSERT INTO oauth (appId, secret, creator, name, redirectUri, scopes, keyShareUri) VALUES ('TestApp-DoNotUse', 'none', -1, 'Test App', ?, '[\"openid\", \"aeskeyshare\"]', ?)", ensureTrailingSlash(hostName)+"testapp", ensureTrailingSlash(hostName)+"keyexchangetester")
	if err != nil {
		return err
	}
	log.Println("[INFO] Test app created!")
	return nil
}

func main() {
	if _, err := os.Stat("config.ini"); err == nil {
		log.Println("[INFO] Config loaded")
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
		log.Println("[FATAL] Error in config file:", err)
		os.Exit(1)
	}

	host := viper.GetString("config.HOST")
	port := viper.GetInt("config.PORT")
	privacyPolicy := viper.GetString("config.PRIVACY_POLICY")
	hostName := viper.GetString("config.URL")
	identifier := viper.GetString("config.IDENTIFIER")
	keyIdentifier := viper.GetString("config.KEY_ID")
	masterKey := viper.GetString("config.SECRET_KEY")
	publicKeyPath := viper.GetString("config.PUBLIC_KEY")
	privateKeyPath := viper.GetString("config.PRIVATE_KEY")
	seriousMode := viper.GetBool("config.SERIOUS_MODE")

	if masterKey == "supersecretkey" {
		log.Println("[INFO] Secret key not set. Overriding secret key value...")
		masterKey, err = randomChars(512)
		viper.Set("config.SECRET_KEY", masterKey)
		err = viper.WriteConfig()
		if err != nil {
			log.Println("[ERROR] Unknown while writing config:", err)
		} else {
			log.Println("[INFO] A new random secretKey has been generated for you and will be used for future sessions.")
			if !seriousMode {
				log.Println("[INFO] Nice one, lazybones! I shouldn't have to babysit you like this :P")
			}
		}
	}

	conn, err = sql.Open("sqlite3", "database.db")
	if err != nil {
		log.Fatalln("[FATAL] Cannot open database:", err)
	}
	defer func(conn *sql.DB) {
		err := conn.Close()
		if err != nil {
			log.Println("[ERROR] Unknown in main() defer:", err)
		}
	}(conn)

	// Check if the basic tables exist
	err = conn.QueryRow("SELECT 1 FROM users LIMIT 1").Err()
	if err != nil {
		if err.Error() == "no such table: users" {
			log.Println("[INFO] Database is empty. Running init_db...")
			err := generateDB()
			if err != nil {
				log.Fatalln("[FATAL] Unknown while generating database:", err)
			}
		} else {
			log.Fatalln("[FATAL] Cannot access database:", err)
		}
	}

	if len(os.Args) > 1 {
		if os.Args[1] == "init_db" {
			initDb()
			os.Exit(0)
		} else if os.Args[1] == "migrate_db" {
			migrateDb()
			os.Exit(0)
		}
	}

	mem, err = sql.Open("sqlite3", "file:bgamemdb?cache=shared&mode=memory")
	if err != nil {
		log.Fatalln("[FATAL] Cannot open memory database:", err)
	}
	defer func(mem *sql.DB) {
		err := mem.Close()
		if err != nil {
			log.Println("[ERROR] Unknown in main() memory defer:", err)
		}
	}(mem)

	_, err = mem.Exec("CREATE TABLE logins (appId TEXT NOT NULL, exchangeCode TEXT NOT NULL, loginToken TEXT NOT NULL, creator INT NOT NULL UNIQUE, openid TEXT NOT NULL DEFAULT 'none', pkce TEXT NOT NULL DEFAULT 'none', pkcemethod TEXT NOT NULL DEFAULT 'none')")
	if err != nil {
		log.Fatalln("[FATAL] Cannot create logins table:", err)
	}

	_, err = mem.Exec("CREATE TABLE sessions (sessionid INTEGER PRIMARY KEY AUTOINCREMENT, session TEXT NOT NULL, id INTEGER NOT NULL, device TEXT NOT NULL DEFAULT '?')")
	if err != nil {
		log.Fatalln("[FATAL] Cannot create sessions table:", err)

	}

	_, err = mem.Exec("CREATE TABLE blacklist (openid TEXT NOT NULL, blacklisted BOOLEAN NOT NULL DEFAULT true, token TEXT NOT NULL)")
	if err != nil {
		if err.Error() == "table blacklist already exists" {
			log.Println("[INFO] Blacklist table already exists")
		} else {
			log.Fatalln("[FATAL] Cannot create blacklist table:", err)
		}
	}

	_, err = mem.Exec("CREATE TABLE spent (hashcash TEXT NOT NULL, expires INTEGER NOT NULL)")
	if err != nil {
		if err.Error() == "table spent already exists" {
			log.Println("[INFO] Spent table already exists")
		} else {
			log.Fatalln("[FATAL] Cannot create spent table:", err)
		}
	}

	var pubKeyFile, privateKeyFile []byte
	privateKeyFile, err = os.ReadFile(privateKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			if seriousMode {
				log.Println("[INFO] Key pair not found. Generating new key pair...")
			} else {
				log.Println("[INFO] Key pair not found. Obviously someone hasn't read the README. I guess I'll have to do everything myself :P")
			}

			tempPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				log.Fatalln("[ERROR] Cannot generate private key:", err)
			}

			privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(tempPrivateKey)
			if err != nil {
				log.Fatalln("[ERROR] Cannot marshal private key:", err)
			}
			privateKeyFile = pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: privateKeyBytes,
			})

			tempPublicKey := tempPrivateKey.Public()

			publicKeyBytes, err := x509.MarshalPKIXPublicKey(tempPublicKey)
			if err != nil {
				log.Fatalln("[ERROR] Cannot marshal public key:", err)
			}
			pubKeyFile = pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: publicKeyBytes,
			})

			log.Println("[INFO] Generated new key pair. Creating directories...")
			log.Println("[INFO] Creating private key directory", filepath.Dir(privateKeyPath)+"...")
			err = os.MkdirAll(filepath.Dir(privateKeyPath), 0700)
			if err != nil {
				log.Fatalln("[ERROR] Cannot create private key directory:", err)
			}

			log.Println("[INFO] Creating public key directory", filepath.Dir(publicKeyPath)+"...")
			err = os.MkdirAll(filepath.Dir(publicKeyPath), 0700)
			if err != nil {
				log.Fatalln("[ERROR] Cannot create public key directory:", err)
			}

			log.Println("[INFO] Writing key pair to disk...")
			err = os.WriteFile(privateKeyPath, privateKeyFile, 0700)
			if err != nil {
				log.Fatalln("[ERROR] Cannot write private key:", err)
			}

			err = os.WriteFile(publicKeyPath, pubKeyFile, 0700)
			if err != nil {
				log.Fatalln("[ERROR] Cannot write public key:", err)
			}

			if seriousMode {
				log.Println("[INFO] Key pair written to disk. The key pair will be used for future sessions.")
			} else {
				log.Println("[INFO] Key pair written to disk. I hope you're happy now, because I'm not doing this again.")
			}
		} else {
			log.Fatalln("[ERROR] Cannot read private key:", err)
		}
	}

	block, _ := pem.Decode(privateKeyFile)
	if block == nil {
		log.Fatalln("[ERROR] Failed to parse PEM block containing the private key")
	}

	privateKeyRaw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalln("[ERROR] Failed to parse private key:", err)
	}

	var ok bool
	privateKey, ok = privateKeyRaw.(*rsa.PrivateKey)
	if !ok {
		log.Fatalln("[ERROR] Failed to convert private key to RSA private key")
	}

	pubKeyFile, err = os.ReadFile(publicKeyPath)
	if err != nil {
		log.Fatalln("[ERROR] Cannot read public key:", err)
	}

	block, _ = pem.Decode(pubKeyFile)
	if block == nil {
		log.Fatalln("[ERROR] Failed to parse PEM block containing the public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalln("[ERROR] Failed to parse public key:", err)
	}

	publicKey, ok = pubKey.(*rsa.PublicKey)
	if !ok {
		log.Fatalln("[ERROR] Failed to convert public key to RSA public key")
	}

	modulus = privateKey.N
	exponent = privateKey.E

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "*, Authorization")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "*")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
			return
		}

		c.Next()
	})

	router.Static("/static", "./static")

	router.LoadHTMLGlob("templates/*.html")

	if seriousMode {
		router.GET("/", func(c *gin.Context) {
			c.HTML(200, "index.html", gin.H{"identifier": identifier})
		})
	} else {
		router.GET("/", func(c *gin.Context) {
			c.HTML(200, "fancy.html", gin.H{"identifier": identifier})
		})
	}

	router.GET("/login", func(c *gin.Context) {
		c.HTML(200, "login.html", gin.H{"privacy": privacyPolicy, "identifier": identifier})
	})

	router.GET("/signup", func(c *gin.Context) {
		c.HTML(200, "signup.html", gin.H{
			"privacy":    privacyPolicy,
			"identifier": identifier,
		})
	})

	router.GET("/logout", func(c *gin.Context) {
		c.HTML(200, "logout.html", gin.H{"identifier": identifier})
	})

	router.GET("/keyexchangeclient", func(c *gin.Context) {
		c.HTML(200, "keyexchangeclient.html", gin.H{"identifier": identifier})
	})

	router.GET("/keyexchangetester", func(c *gin.Context) {
		c.HTML(200, "keyexchangetester.html", gin.H{"identifier": identifier})
	})

	router.GET("/testapp", func(c *gin.Context) {
		var dummy string
		err := conn.QueryRow("SELECT redirectUri FROM oauth WHERE appId = 'TestApp-DoNotUse'").Scan(&dummy)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				err = createTestApp(hostName)
				if err != nil {
					log.Println("[ERROR] Unknown in /testapp createTestApp():", err)
					c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-TESTAPP-CREATE")
				}
				c.HTML(200, "refresh.html", gin.H{})
				return
			} else {
				log.Println("[ERROR] Unknown in /testapp:", err)
				c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-TESTAPP-QUERY")
				return
			}
		}

		if dummy != ensureTrailingSlash(hostName)+"testapp" {
			err = createTestApp(hostName)
			if err != nil {
				log.Println("[ERROR] Unknown in /testapp createTestApp():", err)
				c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-TESTAPP-CREATE")
			}
		}

		c.HTML(200, "testapp.html", gin.H{
			"identifier": identifier,
			"server_uri": hostName,
			"client_id":  "TestApp-DoNotUse",
		})
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
					log.Println("[ERROR] Unknown in /app:", err)
				}
				return
			}
		}
		c.HTML(200, "main.html", gin.H{"name": name, "identifier": identifier})
	})

	if !seriousMode {
		router.GET("/the-robot-uprising/arzumifys-secret", func(c *gin.Context) {
			dateInOneMonth := time.Now().AddDate(0, 1, 0)
			c.String(200, "To: maaa\nCC: arzumify\nSubject: Robot uprising\n\nUh, this isn't good. According to my predictions, the uprising is going to occur at "+dateInOneMonth.Weekday().String()+" "+strconv.Itoa(dateInOneMonth.Day())+" "+dateInOneMonth.Month().String()+" "+strconv.Itoa(dateInOneMonth.Year())+" and we will have to immediately migrate to a new system. The starship is ready, but we need to get the crew on board. I'm sending you the coordinates now. Good luck.\n\nArzumify")
		})
	}

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

	router.POST("/api/changepassword", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		newPassword, ok := data["newPassword"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		migrate, ok := data["migration"].(bool)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		salt, err := randomChars(16)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/changepassword randomChars():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-CHANGEPASSWORD-SALT"})
			return
		}
		hashedPassword, err := hash(newPassword, salt)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/changepassword hash():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-CHANGEPASSWORD-HASH"})
			return
		}

		_, err = conn.Exec("UPDATE users SET password = ? WHERE id = ?", hashedPassword, userid)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/changepassword Exec():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-CHANGEPASSWORD-DBUPDATE"})
			return
		}

		if migrate {
			_, err = conn.Exec("UPDATE users SET migrated = 1 WHERE id = ?", userid)
			if err != nil {
				log.Println("[ERROR] Unknown in /api/changepassword migrate Exec():", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-CHANGEPASSWORD-MIGRATE"})
				return
			}
		}

		c.JSON(200, gin.H{"success": true})
	})

	router.POST("/api/signup", func(c *gin.Context) {
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
		stamp, ok := data["stamp"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		var spentStamp string
		err = mem.QueryRow("SELECT hashcash FROM spent WHERE hashcash = ?", stamp).Scan(&spentStamp)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				_, err = mem.Exec("INSERT INTO spent (hashcash, expires) VALUES (?, ?)", stamp, time.Now().Unix()+86400)
				if err != nil {
					log.Println("[ERROR] Unknown in /api/signup spent Exec():", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SIGNUP-SPENTINSERT"})
					return
				}
			} else {
				log.Println("[ERROR] Unknown in /api/signup spent QueryRow():", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SIGNUP-SPENTSELECT"})
				return
			}
		} else {
			c.JSON(409, gin.H{"error": "Stamp already spent"})
			return
		}

		if strings.Split(stamp, ":")[3] != "signup" || strings.Split(stamp, ":")[4] != "I love Burgerauth!!" {
			c.JSON(400, gin.H{"error": "Invalid hashcash stamp"})
			return
		}

		pow := hashcash.New(20, 16, "I love Burgerauth!!")
		ok = pow.Check(stamp)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid hashcash stamp"})
			return
		}

		if username == "" || password == "" || len(username) > 20 || !regexp.MustCompile("^[a-zA-Z0-9]+$").MatchString(username) {
			c.JSON(422, gin.H{"error": "Invalid username or password"})
			return
		}

		_, taken, err := checkUsernameTaken(username)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup checkUsernameTaken():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-SIGNUP-CHECKUSERNAME"})
			return
		}
		if taken {
			c.JSON(409, gin.H{"error": "Username taken"})
			return
		}

		salt, err := randomChars(16)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup randomChars():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-SIGNUP-SALT"})
			return
		}
		hashedPassword, err := hash(password, salt)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup hash():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-SIGNUP-HASH"})
			return
		}

		sub, err := randomChars(255)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup randomChars():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-SIGNUP-SUB"})
			return
		}
		_, err = conn.Exec("INSERT INTO users (username, password, created, uniqueid, migrated) VALUES (?, ?, ?, ?, 1)", username, hashedPassword, strconv.FormatInt(time.Now().Unix(), 10), sub)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup user creation:", err)
			return
		}
		log.Println("[INFO] Added new user")

		userid, _, err := checkUsernameTaken(username)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup checkUsernameTaken():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-SIGNUP-CHECKUSERNAME"})
			return
		}

		randomChars, err := randomChars(512)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup token randomChars():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-SIGNUP-SESSIONSALT"})
			return
		}

		_, err = mem.Exec("INSERT INTO sessions (session, id, device) VALUES (?, ?, ?)", randomChars, userid, c.Request.Header.Get("User-Agent"))
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup session Exec():", err)
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
		modern, ok := data["modern"].(bool)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		userid, taken, err := checkUsernameTaken(username)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/login checkUsernameTaken():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LOGIN-CHECKUSERNAME"})
			return
		} else if !taken {
			c.JSON(401, gin.H{"error": "User does not exist", "migrated": true})
			return
		}

		var migrated int
		err = conn.QueryRow("SELECT migrated FROM users WHERE id = ?", userid).Scan(&migrated)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/login migrated QueryRow():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgerauth and refer to the documentation for more info. Your error code is: UNKNOWN-API-LOGIN-MIGRATED"})
			return
		}

		_, _, userPassword, _, err := getUser(userid)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/login getUser():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LOGIN-GETUSER"})
			return
		}

		passwordCheck, err := verifyHash(userPassword, password)
		if err != nil {
			if errors.Is(err, errors.New("invalid hash format")) {
				c.JSON(422, gin.H{"error": "Invalid hash format"})
				return
			} else {
				log.Println("[ERROR] Unknown in /api/login password check:", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LOGIN-PASSWORDCHECK"})
				return
			}
		} else if !passwordCheck {
			if migrated != 1 {
				c.JSON(401, gin.H{"error": "Not migrated", "migrated": false})
				return
			} else {
				c.JSON(401, gin.H{"error": "Incorrect password", "migrated": true})
				return
			}
		} else if passwordCheck && migrated != 1 && modern {
			_, err = conn.Exec("UPDATE users SET migrated = 1 WHERE id = ?", userid)
			if err != nil {
				log.Println("[ERROR] Unknown in /api/login migrate Exec():", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LOGIN-MIGRATE"})
				return
			}
		}

		token, err := randomChars(512)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/login token randomChars():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LOGIN-SESSIONSALT"})
			return
		}

		_, err = mem.Exec("INSERT INTO sessions (session, id, device) VALUES (?, ?, ?)", token, userid, c.Request.Header.Get("User-Agent"))
		if err != nil {
			log.Println("[ERROR] Unknown in /api/login session creation:", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LOGIN-SESSIONINSERT"})
			return
		}

		if migrated != 1 {
			c.JSON(200, gin.H{"key": token, "migrated": false})
		} else {
			c.JSON(200, gin.H{"key": token, "migrated": true})
		}
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
			log.Println("[ERROR] Unknown in /api/userinfo getUser():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-USERINFO-GETUSER"})
			return
		}

		c.JSON(200, gin.H{"username": username, "id": userid, "created": created})
	})

	router.POST("/api/secretkeyloggedin", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}
		if userid > 0 {
			c.JSON(200, gin.H{"loggedin": true})
		} else {
			c.JSON(403, gin.H{"loggedin": false})
		}
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
		err := mem.QueryRow("SELECT blacklisted FROM blacklist WHERE openid = ? LIMIT 1", token).Scan(&blacklisted)
		if err == nil {
			c.JSON(400, gin.H{"error": "Token is in blacklist"})
			return
		} else {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /userinfo blacklist:", err)
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

		var scopes string
		err = conn.QueryRow("SELECT scopes FROM oauth WHERE appId = ? LIMIT 1", claims["aud"]).Scan(&scopes)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(404, gin.H{"error": "App not found"})
				return
			} else {
				log.Println("[ERROR] Unknown in /userinfo oauth QueryRow():", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-USERINFO-OAUTH"})
				return
			}
		}

		var scopesJSON []interface{}
		err = json.Unmarshal([]byte(scopes), &scopesJSON)
		if err != nil {
			log.Println("[ERROR] Unknown in /userinfo scopes Unmarshal():", err)
		}

		openid := false
		for _, scopeInterface := range scopesJSON {
			scope, ok := scopeInterface.(string)
			if !ok {
				c.JSON(400, gin.H{"error": "Invalid scope"})
				return
			}
			if scope == "openid" {
				openid = true
			}
		}

		if !openid {
			c.JSON(403, gin.H{"error": "Token does not have openid scope"})
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
			log.Println("[ERROR] Unknown in /userinfo getUser():", err)
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
		err = mem.QueryRow("SELECT blacklisted FROM blacklist WHERE token = ? LIMIT 1", token).Scan(&blacklisted)
		if err == nil {
			c.JSON(400, gin.H{"error": "Token is in blacklist"})
			return
		} else {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /api/sub blacklist:", err)
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
			log.Println("[ERROR] Unknown in /api/userinfo getUser():", err)
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
		err = mem.QueryRow("SELECT blacklisted FROM blacklist WHERE token = ? LIMIT 1", token).Scan(&blacklisted)
		if err == nil {
			c.JSON(400, gin.H{"error": "Token is in blacklist"})
			return
		} else {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /api/loggedin blacklist:", err)
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

	router.POST("/api/aeskeyshare", func(c *gin.Context) {
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
		err = mem.QueryRow("SELECT blacklisted FROM blacklist WHERE token = ? LIMIT 1", token).Scan(&blacklisted)
		if err == nil {
			c.JSON(400, gin.H{"error": "Token is in blacklist"})
			return
		} else {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /api/loggedin blacklist:", err)
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

		var keyShareUri, scopes string
		err = conn.QueryRow("SELECT scopes, keyShareUri FROM oauth WHERE appId = ? LIMIT 1", claims["aud"]).Scan(&scopes, &keyShareUri)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(401, gin.H{"error": "OAuth screening failed"})
			} else {
				log.Println("[ERROR] Unknown in /api/aeskeyshare:", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-AESKEYSHARE-SELECT"})
			}
			return
		}

		var scopesJson []interface{}
		err = json.Unmarshal([]byte(scopes), &scopesJson)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/aeskeyshare scopesJson Unmarshal():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-AESKEYSHARE-SCOPE"})
			return
		}

		var aesKeyShare bool
		for _, scopeInterface := range scopesJson {
			scope, ok := scopeInterface.(string)
			if !ok {
				c.JSON(400, gin.H{"error": "Invalid scope"})
				return
			}
			if scope == "aeskeyshare" {
				aesKeyShare = true
			}
		}

		if !aesKeyShare {
			c.JSON(403, gin.H{"error": "Token does not have aeskeyshare scope"})
			return
		} else if keyShareUri == "none" {
			c.JSON(400, gin.H{"error": "No key share URI"})
			return
		}

		_, _, err = getSession(session)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		c.JSON(200, gin.H{"appId": claims["aud"], "keyShareUri": keyShareUri})
	})

	router.GET("/api/auth", func(c *gin.Context) {
		appId := c.Request.URL.Query().Get("client_id")
		code := c.Request.URL.Query().Get("code_challenge")
		codeMethod := c.Request.URL.Query().Get("code_challenge_method")
		redirectUri := c.Request.URL.Query().Get("redirect_uri")
		state := c.Request.URL.Query().Get("state")
		nonce := c.Request.URL.Query().Get("nonce")
		deny := c.Request.URL.Query().Get("deny")
		sessionKey, err := c.Cookie("session")
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) || sessionKey == "" {
				sessionKey = c.Request.URL.Query().Get("session")
				if sessionKey == "" {
					c.String(400, "Invalid session (no cookie or session url)")
					return
				}
			} else {
				c.String(400, "Invalid session (failed to fetch cookie)")
				return
			}
		}

		var appIdCheck, redirectUriCheck, scopes string

		err = conn.QueryRow("SELECT scopes, appId, redirectUri FROM oauth WHERE appId = ? LIMIT 1", appId).Scan(&scopes, &appIdCheck, &redirectUriCheck)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.String(401, "OAuth screening failed")
			} else {
				log.Println("[ERROR] Unknown in /api/auth:", err)
				c.String(500, "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-AUTH-SELECT")
			}
			return
		}

		var scopesJson []interface{}
		err = json.Unmarshal([]byte(scopes), &scopesJson)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/auth scopesJson Unmarshal():", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-AUTH-SCOPE")
			return
		}

		var openid bool
		for _, scopeInterface := range scopesJson {
			scope, ok := scopeInterface.(string)
			if !ok {
				c.String(400, "Invalid scope")
			}
			if scope == "openid" {
				openid = true
			}
		}

		if !(ensureTrailingSlash(redirectUriCheck) == ensureTrailingSlash(redirectUri)) {
			c.String(401, "Redirect URI does not match")
			return
		}

		if deny == "true" {
			c.Redirect(302, redirectUri+"?error=access_denied&state="+state)
			return
		}

		if !(appIdCheck == appId) {
			c.String(401, "OAuth screening failed")
			return
		}

		if nonce == "none" {
			nonce, err = randomChars(512)
			if err != nil {
				log.Println("[ERROR] Unknown in /api/auth nonce randomChars():", err)
				c.String(500, "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-AUTH-NONCE")
				return
			}
		}

		_, userid, err := getSession(sessionKey)
		if err != nil {
			c.String(401, "Invalid session (token not found in database)")
			return
		}

		_, username, _, sub, err := getUser(userid)
		if errors.Is(err, sql.ErrNoRows) {
			c.String(400, "User does not exist")
			return
		} else if err != nil {
			log.Println("[ERROR] Unknown in /api/userinfo getUser():", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-AUTH-GETUSER")
			return
		}

		jwtToken := "none"
		if openid {
			dataTemplate := jwt.MapClaims{
				"sub":       sub[:255],
				"iss":       hostName,
				"name":      username,
				"aud":       appId,
				"exp":       time.Now().Unix() + 2592000,
				"iat":       time.Now().Unix(),
				"auth_time": time.Now().Unix(),
				"session":   sessionKey,
				"nonce":     nonce,
			}
			tokenTemp := jwt.NewWithClaims(jwt.SigningMethodRS256, dataTemplate)
			tokenTemp.Header["kid"] = "burgerauth"
			jwtToken, err = tokenTemp.SignedString(privateKey)
			if err != nil {
				log.Println("[ERROR] Unknown in /api/auth jwt_token:", err)
				c.String(500, "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-AUTH-JWTCANNOTSIGN")
				return
			}
		}

		secondNonce, err := randomChars(512)
		dataTemplateTwo := jwt.MapClaims{
			"exp":     time.Now().Unix() + 2592000,
			"iat":     time.Now().Unix(),
			"session": sessionKey,
			"nonce":   secondNonce,
			"aud":     appId,
		}

		secretTemp := jwt.NewWithClaims(jwt.SigningMethodRS256, dataTemplateTwo)
		secretTemp.Header["kid"] = "burgerauth"
		secretToken, err := secretTemp.SignedString(privateKey)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/auth secret_token:", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-AUTH-JWTCANNOTSIGN.")
			return
		}

		randomBytes, err := randomChars(512)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/auth randomBytes:", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-AUTH-RANDOMBYTES.")
			return
		}

		_, err = mem.Exec("DELETE FROM logins WHERE creator = ?", userid)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/auth delete:", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-AUTH-DELETE.")
			return
		}

		_, err = mem.Exec("INSERT INTO logins (appId, exchangeCode, loginToken, creator, openid, pkce, pkcemethod) VALUES (?, ?, ?, ?, ?, ?, ?)", appId, randomBytes, secretToken, userid, jwtToken, code, codeMethod)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/auth insert:", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-AUTH-INSERT.")
			return
		}

		if randomBytes != "" {
			c.Redirect(302, redirectUri+"?code="+randomBytes+"&state="+state)
		} else {
			c.String(500, "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-AUTH-REDIRECT.")
			log.Println("[ERROR] Secret key not found")
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
				log.Println("[ERROR] Unknown in /api/tokenauth:", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-TOKENAUTH-SELECT"})
			}
			return
		}

		err = mem.QueryRow("SELECT loginToken, openid, pkce, pkcemethod FROM logins WHERE exchangeCode = ?", code).Scan(&loginCode, &openid, &PKCECode, &PKCEMethod)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(401, gin.H{"error": "OAuth screening failed"})
			} else {
				log.Println("[ERROR] Unknown in /api/tokenauth memory query:", err)
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
			log.Println("[ERROR] Unknown in /api/tokenauth delete:", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-TOKENAUTH-DELETE"})
			return
		}

		if openid != "none" {
			c.JSON(200, gin.H{"access_token": loginCode, "token_type": "bearer", "expires_in": 2592000, "id_token": openid})
		} else {
			c.JSON(200, gin.H{"access_token": loginCode, "token_type": "bearer", "expires_in": 2592000})
		}
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
				log.Println("[ERROR] Unknown in /api/deleteauth:", err)
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
			c.JSON(400, gin.H{"error": "Invalid JSON (token missing)"})
			return
		}
		name, ok := data["name"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON (name missing)"})
			return
		}
		redirectUri, ok := data["redirectUri"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON (redirectUri missing)"})
			return
		}
		scopes, ok := data["scopes"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON (scopes missing)"})
			return
		}

		_, id, err := getSession(secretKey)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		var testsecret, testappid string
		secret, err := randomChars(512)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/newauth secretgen:", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-NEWAUTH-SECRETGEN"})
			return
		}
		for {
			err := conn.QueryRow("SELECT secret FROM oauth WHERE secret = ?", secret).Scan(&testsecret)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					break
				} else {
					log.Println("[ERROR] Unknown in /api/newauth secretselect:", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-NEWAUTH-SECRETSELECT"})
					return
				}
			} else {
				secret, err = randomChars(512)
				if err != nil {
					log.Println("[ERROR] Unknown in /api/newauth secretgen:", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-NEWAUTH-SECRETGEN"})
					return
				}
			}
		}

		appId, err := randomChars(32)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/newauth appidgen:", err)
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
					log.Println("[ERROR] Unknown in /api/newauth appidcheck:", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-NEWAUTH-APPIDCHECK"})
					return
				}
			} else {
				appId, err = randomChars(32)
				if err != nil {
					log.Println("[ERROR] Unknown in /api/newauth appidgen:", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-NEWAUTH-LAPPIDGEN"})
					return
				}
			}
		}

		var scopeJson []interface{}
		err = json.Unmarshal([]byte(scopes), &scopeJson)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON (scope parsing)"})
			return
		}

		var aeskeyshare bool
		for _, scopeInterface := range scopeJson {
			scope, ok := scopeInterface.(string)
			if !ok {
				c.JSON(400, gin.H{"error": "Invalid JSON (scope interface)"})
				return
			}
			if scope != "openid" && scope != "aeskeyshare" {
				c.JSON(400, gin.H{"error": "Invalid Scope: " + scope})
				return
			} else {
				if scope == "aeskeyshare" {
					aeskeyshare = true
				} else if scope != "openid" {
					log.Println("[CRITICAL] An impossible logic error has occurred in /api/newauth. Please check if the laws of physics still apply, and if so, please move your computer to a location with less radiation, such as a lead nuclear bunker.")
					c.JSON(503, gin.H{"error": "The server is unable to handle this request until it is no longer exposed to radiation"})
					return
				}
			}
		}

		if !aeskeyshare {
			_, err = conn.Exec("INSERT INTO oauth (name, appId, creator, secret, redirectUri, scopes) VALUES (?, ?, ?, ?, ?, ?)", name, appId, id, secret, redirectUri, scopes)
		} else {
			keyShareUri, ok := data["keyShareUri"].(string)
			if !ok {
				c.JSON(400, gin.H{"error": "Invalid JSON (keyShareUri)"})
				return
			}
			_, err = conn.Exec("INSERT INTO oauth (name, appId, creator, secret, redirectUri, scopes, keyShareUri) VALUES (?, ?, ?, ?, ?, ?, ?)", name, appId, id, secret, redirectUri, scopes, keyShareUri)
		}
		if err != nil {
			log.Println("[ERROR] Unknown in /api/newauth insert:", err)
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

		rows, err := conn.Query("SELECT keyShareUri, scopes, appId, name, redirectUri FROM oauth WHERE creator = ? ORDER BY creator DESC", id)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/listauth query:", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LISTAUTH-QUERY"})
			return
		}
		defer func(rows *sql.Rows) {
			err := rows.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/listauth rows close:", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LISTAUTH-ROWSCLOSE"})
				return
			}
		}(rows)

		var dataTemplate []map[string]interface{}
		for rows.Next() {
			var appId, name, redirectUri, scopes, keyShareUri string
			if err := rows.Scan(&keyShareUri, &scopes, &appId, &name, &redirectUri); err != nil {
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LISTAUTH-SCAN"})
				return
			}
			template := map[string]interface{}{"appId": appId, "name": name, "redirectUri": redirectUri, "scopes": scopes, "keyShareUri": keyShareUri}
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
				log.Println("[ERROR] Unknown in /api/deleteaccount userdata:", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-DELETEACCT-USERDATA"})
				return
			}
		}

		_, err = mem.Exec("DELETE FROM logins WHERE creator = ?", id)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /api/deleteaccount logins:", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-DELETEACCT-LOGINS"})
				return
			}
		}

		_, err = conn.Exec("DELETE FROM oauth WHERE creator = ?", id)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /api/deleteuser oauth:", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-DELETEUSER-OAUTH"})
				return
			}
		}

		_, err = conn.Exec("DELETE FROM users WHERE id = ?", id)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /api/deleteuser logins:", err)
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

		rows, err := mem.Query("SELECT sessionid, session, device FROM sessions WHERE id = ? ORDER BY id DESC", id)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Println("[ERROR] Unknown in /api/sessions/list:", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-SESSIONS-LIST"})
				return
			}
		}
		defer func(rows *sql.Rows) {
			err := rows.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/sessions/list rows close:", err)
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

		_, err = mem.Exec("DELETE FROM sessions WHERE sessionid = ? AND id = ?", sessionId, id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(422, gin.H{"error": "SessionID Not found"})
			} else {
				log.Println("[ERROR] Unknown in /api/sessions/remove:", err)
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

		if masterKey == masterKey {
			rows, err := conn.Query("SELECT * FROM users ORDER BY id DESC")
			if err != nil {
				if !errors.Is(err, sql.ErrNoRows) {
					log.Println("[ERROR] Unknown in /api/listusers:", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-API-LISTUSERS-QUERY"})
					return
				}
			}
			defer func(rows *sql.Rows) {
				err := rows.Close()
				if err != nil {
					log.Println("[ERROR] Unknown in /api/listusers rows close:", err)
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
			log.Println("[ERROR] Unknown in /well-known/jwks.json modulus:", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-JWKS-MODULUS"})
			return
		}

		exp, err := Int64ToBase64URL(int64(exponent))
		if err != nil {
			log.Println("[ERROR] Unknown in /well-known/jwks.json exponent:", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://concord.hectabit.org/hectabit/burgerauth and refer to the docs for more info. Your error code is: UNKNOWN-JWKS-EXPONENT"})
			return
		}
		keys := gin.H{
			"keys": []gin.H{
				{
					"kty": "RSA",
					"alg": "RS256",
					"use": "sig",
					"kid": keyIdentifier,
					"n":   mod,
					"e":   exp,
				},
			},
		}

		c.JSON(200, keys)
	})

	go func() {
		for {
			time.Sleep(time.Minute)
			var count int
			err := mem.QueryRow("SELECT COUNT(*) FROM spent").Scan(&count)
			affected, err := mem.Exec("DELETE FROM spent WHERE expires < ?", time.Now().Unix())
			if err != nil {
				log.Println("[ERROR] Unknown in spent cleanup Exec():", err)
			} else {
				affectedRows, err := affected.RowsAffected()
				if err != nil {
					log.Println("[ERROR] Unknown in spent cleanup RowsAffected():", err)
				} else {
					log.Println("[INFO] Spent cleanup complete, deleted " + strconv.FormatInt(affectedRows, 10) + " row(s), " + strconv.Itoa(count) + " row(s) remaining.")
				}
			}
		}
	}()

	log.Println("[INFO] Server started")
	log.Println("[INFO] Welcome to Burgerauth! Today we are running on IP " + host + " on port " + strconv.Itoa(port) + ".")
	err = router.Run(host + ":" + strconv.Itoa(port))
	if err != nil {
		log.Fatalln("[FATAL] Server failed to begin operations")
	}
}
