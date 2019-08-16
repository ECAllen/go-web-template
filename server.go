package main

import (
  // general
	"errors"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"

  // web stuff
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/middleware"

  // database stuff
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"strconv"

  // config stuff
	"github.com/spf13/viper"

  // store pws
	"github.com/alexedwards/argon2id"
)

func accessible(c echo.Context) error {
	return c.String(http.StatusOK, "Accessible")
}

func restricted(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	name := claims["name"].(string)
	return c.String(http.StatusOK, "Welcome "+name+"!")
}

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

func Index(c echo.Context) error {
	return c.Render(http.StatusOK, "index", map[string]interface{}{})
}

func Admin(c echo.Context) error {
	sess, _ := session.Get("session", c)
	authorized := sess.Values["auth"]
	if authorized == "true" {
		return c.Render(http.StatusOK, "authorized", map[string]interface{}{})
	}
	return c.Render(http.StatusUnauthorized, "unauthorized", map[string]interface{}{})
}

func Login(c echo.Context) error {

	user := c.FormValue("username")
	authorized := false

	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
	}

	// Database
	database, err := sql.Open("sqlite3", "./statmeet.db")
	if err != nil {
		log.Fatal(err)
	}

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

	if username == "test" {
		authorized = true
	}

	sess.Values["auth"] = authorized

	sess.Save(c.Request(), c.Response())

	if authorized {
		return c.Render(http.StatusOK, "login", map[string]interface{}{})
	}

	return c.Render(http.StatusUnauthorized, "unauthorized", map[string]interface{}{})
}

func main() {

	// Load Configs
	viper.AddConfigPath("./configs")
	viper.AddConfigPath("$HOME/configs")
	viper.SetConfigName("env")
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file, %s", err)
	}

	// Confirm which config file is used
	fmt.Printf("Using config: %s\n", viper.ConfigFileUsed())

	appName := viper.Get("app.name") 
	fmt.Printf("Value: %v, Type: %T\n", appName, appName)


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

	// Setup the database
	database, _ := sql.Open("sqlite3", "./statmeet.db")
	statement, _ := database.Prepare("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
	statement.Exec()
	insert_user, _ := database.Prepare("INSERT INTO users (username, password) VALUES (?, ?)")
	insert_user.Exec("test", "test")
	database.Close()

	// Setup echo
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	// TODO should session key be moved to viper?
	e.Use(session.Middleware(sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))))

	// Templates
	templates := make(map[string]*template.Template)
	templates["index"] = template.Must(template.ParseFiles("public/views/index.html", "public/views/loginbar.html", "public/views/base.html"))
	templates["login"] = template.Must(template.ParseFiles("public/views/login.html", "public/views/loggedinbar.html", "public/views/base.html"))
	templates["unauthorized"] = template.Must(template.ParseFiles("public/views/unauthorized.html", "public/views/loginbar.html", "public/views/base.html"))

	e.Renderer = &TemplateRegistry{
		templates: templates,
	}

	// Routes
	e.GET("/", Index)
	e.POST("/login", Login)
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
