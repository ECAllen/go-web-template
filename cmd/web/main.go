package main

/* Notes

Add License

DO NOT USE yet, Shit code needs serious cleaning

TODO 

*/
import (
	// general
	"os"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"time"

	// web stuff
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"

	// database stuff
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	/*
		"database/sql"
		"fmt"
		_ "github.com/mattn/go-sqlite3"
		"strconv"
	*/
	// config stuff
	"github.com/spf13/viper"
	// pws
	"github.com/alexedwards/argon2id"
)

// Types
// Dependency injection
type application struct {
	errorLog *log.Logger
	infoLog  *log.Logger
	users	 *UserStore
}

type User struct {
        gorm.Model
        Username string `gorm:"unique_index;not null"`
        Email    string `gorm:"unique_index;not null"`
        Password string `gorm:"not null"`
}

// Database
func AutoMigrate(db *gorm.DB) {
	db.AutoMigrate(
		&User{},
	)
}

type UserStore struct {
    db *gorm.DB
}

func NewUserStore(db *gorm.DB) *UserStore {
    return &UserStore{
        db: db,
    }
}

// Templates
type TemplateRegistry struct {
	templates map[string]*template.Template
}

func (t *TemplateRegistry) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	tmpl, ok := t.templates[name]
	if !ok {
		err := errors.New("Template not found -> " + name)
		return err
	}
	return tmpl.ExecuteTemplate(w, "base", data)
}

func restricted(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	name := claims["name"].(string)
	return c.String(http.StatusOK, "Welcome "+name+"!")
}

func Index(c echo.Context) error {
	return c.Render(http.StatusOK, "index", map[string]interface{}{})
}

func Admin(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	admin := claims["admin"].(bool)
	if admin {
		return c.Render(http.StatusOK, "authorized", map[string]interface{}{})
	}
	return c.Render(http.StatusUnauthorized, "unauthorized", map[string]interface{}{})
}

func Create(c echo.Context) error {
	return c.Render(http.StatusOK, "create", map[string]interface{}{})
}

func (app *application) Login(c echo.Context) error {
	// SQLite
	/*
			database, err := sql.Open("sqlite3", "./statmeet.db")
			if err != nil {
				log.Fatal(err)
			}
		  // TODO defer close

		  rows, err := database.Query("SELECT id, username, password FROM users WHERE username=?", user)
			if err != nil {
				log.Fatal(err)
			}
			var id int
			var username string
			var password string
			for rows.Next() {
				rows.Scan(&id, &username, &password)
				fmt.Println(strconv.Itoa(id) + ": " + username + " " + password)
			}
			rows.Close()
			database.Close()
	*/
	// user := c.FormValue("username")
	pw := c.FormValue("password")

	// TODO get hash from db after create cycle is coded up
	hash := "blah"

	match, err := argon2id.ComparePasswordAndHash(pw, hash)
	if err != nil {
		log.Fatal(err)
	}

	if !match {
		return c.Render(http.StatusUnauthorized, "unauthorized", map[string]interface{}{})
	}

	token := jwt.New(jwt.SigningMethodHS256)

	claims  := token.Claims.(jwt.MapClaims)
	claims["name"] = "Ron Paul"
	claims["admin"] = true
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

	t, err := token.SignedString([]byte("liberty"))
	if err != nil {
		return err
	}

	return c.Render(http.StatusOK, "authorized", map[string]interface{}{
		"token": t,})

}

func main() {

	// Logging
	infoLog := log.New(os.Stdout, "INFO\t", log.Ldate|log.Ltime)
	errorLog := log.New(os.Stderr, "ERROR\t", log.Ldate|log.Ltime)


	// Load Configs
	viper.AddConfigPath("./configs")
	viper.AddConfigPath("$HOME/configs")
	viper.SetConfigName("env")
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file, %s", err)
	}
	session_key := viper.GetString("session_key")

	// Confirm which config file is used
	fmt.Printf("Using config: %s\n", viper.ConfigFileUsed())

	// Database
	// Gorm sqlite
	database, err := gorm.Open("sqlite3", "./statmeet.db")
	if err != nil {
		log.Fatal(err)
	}
	database.LogMode(true)
	defer database.Close()
	database.AutoMigrate(&User{})

	userStore := NewUserStore(database)

	app := &application{
		errorLog: errorLog,
		infoLog: infoLog,
		users: userStore,
	}
	/*

	   	Changing the Parameters

	   When creating a hash you can and should configure the parameters to be suitable for the environment that the code is running in. The parameters are:

	       Memory — The amount of memory used by the Argon2 algorithm (in kibibytes).
	       Iterations — The number of iterations (or passes) over the memory.
	       Parallelism — The number of threads (or lanes) used by the algorithm.
	       Salt length — Length of the random salt. 16 bytes is recommended for password hashing.
	       Key length — Length of the generated key (or password hash). 16 bytes or more is recommended.

	   The Memory and Iterations parameters control the computational cost of hashing the password. The higher these figures are, the greater the cost of generating the hash and the longer the runtime. It also follows that the greater the cost will be for any attacker trying to guess the password.

	   If the code is running on a machine with multiple cores, then you can decrease the runtime without reducing the cost by increasing the Parallelism parameter. This controls the number of threads that the work is spread across. Important note: Changing the value of the Parallelism parameter changes the hash output.

	   params := &Params{
	   	Memory:      128 * 1024,
	   	Iterations:  4,
	   	Parallelism: 4,
	   	SaltLength:  16,
	   	KeyLength:   32,
	   }


	   hash, err := argon2id.CreateHash("pa$$word", argon2id.DefaultParams)
	   if err != nil {
	   	log.Fatal(err)
	   }

	   For guidance and an outline process for choosing appropriate parameters see https://tools.ietf.org/html/draft-irtf-cfrg-argon2-04#section-4.
	   	// CreateHash returns a Argon2id hash of a plain-text password using the
	   	// provided algorithm parameters. The returned hash follows the format used
	   	// by the Argon2 reference C implementation and looks like this:
	   	// $argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
	   	hash, err := argon2id.CreateHash("pa$$word", argon2id.DefaultParams)
	   	if err != nil {
	   		log.Fatal(err)
	   	}

	   	// ComparePasswordAndHash performs a constant-time comparison between a
	   	// plain-text password and Argon2id hash, using the parameters and salt
	   	// contained in the hash. It returns true if they match, otherwise it returns
	   	// false.
	   	match, err := argon2id.ComparePasswordAndHash("pa$$word", hash)
	   	if err != nil {
	   		log.Fatal(err)
	   	}

	   	log.Printf("Match: %v", match)

	*/

	// Setup echo
	e := echo.New()
	e.Pre(middleware.RemoveTrailingSlash())
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.Secure())

	// Templates
	templates := make(map[string]*template.Template)
	templates["index"] = template.Must(template.ParseFiles("public/views/index.html", "public/views/loginbar.html", "public/views/base.html"))
	templates["login"] = template.Must(template.ParseFiles("public/views/login.html", "public/views/loggedinbar.html", "public/views/base.html"))
	templates["admin"] = template.Must(template.ParseFiles("public/views/admin.html", "public/views/loggedinbar.html", "public/views/base.html"))
	templates["create"] = template.Must(template.ParseFiles("public/views/create.html", "public/views/base.html"))
	templates["unauthorized"] = template.Must(template.ParseFiles("public/views/unauthorized.html", "public/views/loginbar.html", "public/views/base.html"))

	e.Renderer = &TemplateRegistry{
		templates: templates,
	}

	// Routes
	e.GET("/", Index)
	e.POST("/login", Login)
	e.POST("/create", Create)

	admin := e.Group("/admin")
	admin.Use(middleware.JWT([]byte(session_key)))
	admin.GET("/", Admin)

	// Let 'er rip...
	e.Logger.Fatal(e.Start(":8000"))
}

// Rules/Logic
// cards can reference other cards
// cards have fields
// sort priotory

// Stats
// user defined
// priority
// dates
// est time

// Objects
// queue
// stack
// card
// user
// connection
