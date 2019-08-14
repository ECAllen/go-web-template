package main

import (
	"errors"
	"html/template"
	"io"
	"net/http"
	"os"
	"log"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/middleware"

	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"fmt"
	"strconv"
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

	rows, err := database.Query("SELECT id, username, password FROM users WHERE username=?",user)
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

	// Database
	database, _ := sql.Open("sqlite3", "./statmeet.db")
	statement, _ := database.Prepare("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
	statement.Exec()
	insert_user, _ := database.Prepare("INSERT INTO users (username, password) VALUES (?, ?)")
	insert_user.Exec("test", "test")
	database.Close()

	// Setup Echo
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
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
