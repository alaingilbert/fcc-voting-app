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
	e.GET("/", mainHandler)
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
