package main

import (
	"fmt"
	"github.com/labstack/echo"
	"github.com/urfave/cli"
	"html/template"
	"os"
)

type H map[string]interface{}

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	var files []string
	files = append(files, "public/templates/base.html")
	files = append(files, fmt.Sprintf("public/templates/%s.html", name))
	tmpl := template.Must(template.ParseFiles(files...))
	return tmpl.Execute(w, data)
}

type User struct {
	ID         bson.ObjectId `bson:"_id"`
	NickName   string
	TwitterID  string
	SessionKey string
}

type Vote struct {
	ID        bson.ObjectId `bson:"_id"`
	IP        *string
	Author    *string
	Choice    string
	CreatedAt time.Time
}

type Poll struct {
	ID        bson.ObjectId `json:"id" bson:"_id"`
	Title     string        `json:"title"`
	Answers   []string      `json:"answers"`
	Author    string        `json:"author"`
	CreatedAt time.Time     `json:"create_at"`
	Votes     []Vote
}
func mainHandler(c echo.Context) error {
	return c.String(200, "Hello World")
func authTwitterHandler(c echo.Context) error {
	// try to get the user without re-authenticating
	res := c.Response()
	req := c.Request()
	if user, err := gothic.CompleteUserAuth(res, req); err == nil {
		s := session.Copy()
		defer s.Close()
		key, _ := time.Now().MarshalText()
		token := hex.EncodeToString(hmac.New(sha256.New, key).Sum(nil))
		cc := s.DB("poll").C("users")
		if err := cc.Update(bson.M{"twitterid": user.UserID}, bson.M{"$set": bson.M{"sessionkey": token}}); err != nil {
			if !mgo.IsDup(err) {
				return err
			}
		}
		cookie := http.Cookie{Name: "auth-token", Value: token, Path: "/"}
		http.SetCookie(c.Response().Writer, &cookie)
		return c.Redirect(303, "/")
	} else {
		gothic.BeginAuthHandler(res, req)
		return nil
	}
}

func authTwitterCallbackHandler(c echo.Context) error {
	user, err := gothic.CompleteUserAuth(c.Response(), c.Request())
	if err != nil {
		return err
	}

	s := session.Copy()
	defer s.Close()
	key, _ := time.Now().MarshalText()
	token := hex.EncodeToString(hmac.New(sha256.New, key).Sum(nil))
	var u User
	u.ID = bson.NewObjectId()
	u.NickName = user.NickName
	u.TwitterID = user.UserID
	u.SessionKey = token
	cc := s.DB("poll").C("users")
	if err := cc.Insert(u); err != nil {
		if !mgo.IsDup(err) {
			return err
		}
	}

	cookie := http.Cookie{Name: "auth-token", Value: token, Path: "/"}
	http.SetCookie(c.Response().Writer, &cookie)
	return c.Redirect(303, "/")
}

func logoutHandler(c echo.Context) error {
	//cookie := &http.Cookie{
	//	Name:   fmt.Sprintf("twitter%s", gothic.SessionName),
	//	Value:  "",
	//	Path:   "/",
	//	MaxAge: -1,
	//}
	//http.SetCookie(c.Response(), cookie)
	cookie := http.Cookie{Name: "auth-token", Value: "", Path: "/"}
	c.SetCookie(&cookie)
	return c.Redirect(302, "/")
}

func setUserMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		authCookie, err := c.Cookie("auth-token")
		if err != nil {
			fmt.Println("cannot read auth-token", err)
		}
		s := session.Copy()
		defer s.Close()
		cc := s.DB("poll").C("users")
		var user User
		if err := cc.Find(bson.M{"sessionkey": authCookie.Value}).One(&user); err != nil {
		}
		c.Set("user", user)
		return next(c)
	}
}

func ensureIndex(s *mgo.Session) {
	s2 := s.Copy()
	defer s2.Close()
	c := session.DB("poll").C("users")
	index := mgo.Index{
		Key:        []string{"twitterid"},
		Unique:     true,
		DropDups:   true,
		Background: true,
		Sparse:     true,
	}
	err := c.EnsureIndex(index)
	if err != nil {
		panic(err)
	}
}

func start(c *cli.Context) error {
	ensureIndex(session)

	t := &Template{}
	port := c.Int("port")
	e := echo.New()
	e.Use(setUserMiddleware)
	e.GET("/", mainHandler)
	e.GET("/auth/:provider", authTwitterHandler)
	e.GET("/auth/:provider/callback", authTwitterCallbackHandler)
	e.GET("/logout", logoutHandler)
	e.Logger.Fatal(e.Start(fmt.Sprintf(":%d", port)))
	return nil
}

func main() {
	app := cli.NewApp()
	app.Author = "Alain Gilbert"
	app.Email = "alain.gilbert.15@gmail.com"
	app.Name = "File Metadata Microservice"
	app.Usage = "File Metadata Microservice"
	app.Version = "0.0.1"
	app.Flags = []cli.Flag{
		cli.IntFlag{
			Name:   "port",
			Value:  3001,
			Usage:  "Webserver port",
			EnvVar: "PORT",
		},
	}
	app.Action = start
	app.Run(os.Args)
}
