package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
	"github.com/labstack/gommon/log"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/twitter"
	"github.com/urfave/cli"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"html/template"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type H map[string]interface{}

var session *mgo.Session

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

func getPolls() []Poll {
	s := session.Copy()
	defer s.Close()
	c := s.DB("poll").C("polls")
	var polls []Poll
	err := c.Find(bson.M{}).All(&polls)
	if err != nil {
		fmt.Println(err)
		return polls
	}
	return polls
}

func mainHandler(c echo.Context) error {
	polls := getPolls()
	data := H{"polls": polls, "user": c.Get("user")}
	return c.Render(200, "index", data)
}

func newPollHandler(c echo.Context) error {
	data := H{"user": c.Get("user")}
	return c.Render(200, "new-poll", data)
}

func RemoveDuplicates(slice []string) []string {
	length := len(slice) - 1
	for i := 0; i < length; i++ {
		for j := i + 1; j <= length; j++ {
			if slice[i] == slice[j] {
				slice[j] = slice[length]
				slice = slice[0:length]
				length--
				j--
			}
		}
	}
	return slice
}

func RemoveEmpty(slice []string) []string {
	length := len(slice) - 1
	for i := 0; i <= length; i++ {
		slice[i] = strings.Trim(slice[i], " \r\n\t")
		if slice[i] == "" {
			slice[i] = slice[length]
			slice = slice[0:length]
			length--
		}
	}
	return slice
}

func sanitizeChoices(choices string) []string {
	c := strings.Split(choices, "\r\n")
	c = RemoveDuplicates(c)
	c = RemoveEmpty(c)
	return c
}

func createNewPollHandler(c echo.Context) error {
	s := session.Copy()
	defer s.Close()
	user := c.Get("user").(User)
	title := strings.Trim(c.FormValue("title"), " \t\n\r")
	answersForm := c.FormValue("answers")
	answers := sanitizeChoices(answersForm)
	if len(title) < 3 {
		data := H{"user": user, "title": title, "answers": answersForm, "error": "Title must have at least 3 charaters"}
		return c.Render(200, "new-poll", data)
	}
	if len(answers) < 2 {
		data := H{"user": user, "title": title, "answers": answersForm, "error": "You must have at least 2 unique choices"}
		return c.Render(200, "new-poll", data)
	}
	var poll Poll
	poll.ID = bson.NewObjectId()
	poll.Title = title
	poll.Answers = answers
	poll.Author = user.TwitterID
	poll.CreatedAt = time.Now()
	cc := s.DB("poll").C("polls")
	err := cc.Insert(poll)
	if err != nil {
		return err
	}
	return c.Redirect(303, fmt.Sprintf("/polls/%s", poll.ID.Hex()))
}

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

func accountHandler(c echo.Context) error {
	user, err := gothic.CompleteUserAuth(c.Response(), c.Request())
	if err != nil {
		return c.Redirect(302, "/")
	}
	data := H{"user": user}
	return c.Render(200, "user", data)
}

func getProvider(req *http.Request) (string, error) {
	return "twitter", nil
}

func IsAuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		user := c.Get("user").(User)
		if user.TwitterID == "" {
			return c.Redirect(302, "/")
		}
		return next(c)
	}
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

func getVotesAggrForPoll(s *mgo.Session, pollID string) ([]bson.M, error) {
	cc := s.DB("poll").C("polls")
	match := bson.M{"$match": bson.M{"_id": bson.ObjectIdHex(pollID)}}
	project := bson.M{"$project": bson.M{"votes": 1}}
	unwind := bson.M{"$unwind": "$votes"}
	group := bson.M{"$group": bson.M{"_id": "$votes.choice", "count": bson.M{"$sum": 1}}}
	pipe := cc.Pipe([]bson.M{match, project, unwind, group})
	var results []bson.M
	err := pipe.All(&results)
	return results, err
}

func pollHandler(c echo.Context) error {
	pollID := c.Param("id")
	user := c.Get("user").(User)
	ip := c.RealIP()
	s := session.Copy()
	defer s.Close()
	cc := s.DB("poll").C("polls")
	var poll Poll
	if err := cc.Find(bson.M{"_id": bson.ObjectIdHex(pollID)}).One(&poll); err != nil {
		return c.Redirect(302, "/")
	}
	data := H{"user": user, "poll": poll}
	alreadyVoted := hasUserVotedOnPoll(s, user.TwitterID, ip, pollID)
	data["already_voted"] = alreadyVoted
	if alreadyVoted {
		aggr, _ := getVotesAggrForPoll(s, pollID)
		data["aggr"] = aggr
	}
	return c.Render(200, "poll", data)
}

func myPollsHandler(c echo.Context) error {
	user := c.Get("user").(User)
	s := session.Copy()
	defer s.Close()
	cc := s.DB("poll").C("polls")
	var polls []Poll
	err := cc.Find(bson.M{"author": user.TwitterID}).All(&polls)
	if err != nil {
		fmt.Println(err)
		return c.Redirect(302, "/")
	}
	data := H{"user": user, "polls": polls}
	return c.Render(200, "my-polls", data)
}

func deletePollHandler(c echo.Context) error {
	user := c.Get("user").(User)
	s := session.Copy()
	defer s.Close()
	cc := s.DB("poll").C("polls")
	err := cc.Remove(bson.M{"_id": bson.ObjectIdHex(c.Param("id")), "author": user.TwitterID})
	if err != nil {
		fmt.Println(err)
		return c.Redirect(302, "/mypolls")
	}
	return c.Redirect(302, "/mypolls")
}

func hasUserVotedOnPoll(s *mgo.Session, userID, IP, pollID string) bool {
	cc := s.DB("poll").C("polls")
	err := cc.Find(bson.M{
		"_id": bson.ObjectIdHex(pollID),
		"votes": bson.M{
			"$elemMatch": bson.M{
				"$or": []interface{}{
					bson.M{"author": userID},
					bson.M{"ip": IP},
				},
			},
		}}).One(&Poll{})
	return err == nil
}

func inArray(needle string, haystack []string) bool {
	found := false
	for i := 0; i < len(haystack); i++ {
		if needle == haystack[i] {
			found = true
			break
		}
	}
	return found
}

func voteHandler(c echo.Context) error {
	user := c.Get("user").(User)
	ip := c.RealIP()
	pollID := c.Param("id")
	choice := c.FormValue("choice")

	s := session.Copy()
	defer s.Close()
	cc := s.DB("poll").C("polls")

	if hasUserVotedOnPoll(s, user.TwitterID, ip, pollID) {
		return c.String(400, "You can't vote twice")
	}

	var poll Poll
	if err := cc.Find(bson.M{"_id": bson.ObjectIdHex(pollID)}).One(&poll); err != nil {
		return c.String(404, "Poll not found")
	}
	vote := Vote{}
	vote.ID = bson.NewObjectId()
	vote.IP = &ip
	if user.TwitterID != "" {
		vote.Author = &user.TwitterID
	}
	if choice == "" {
		if user.TwitterID == "" {
			return c.String(400, "You have to be authenticated to create a new choice")
		}
		newChoice := strings.Trim(c.FormValue("other_choice"), " \n\r\t")
		if newChoice == "" {
			return c.String(400, "You cannot leave an empty vote")
		}
		if !inArray(newChoice, poll.Answers) {
			poll.Answers = append(poll.Answers, newChoice)
		}
		vote.Choice = newChoice
	} else {
		vote.Choice = choice
	}
	poll.Votes = append(poll.Votes, vote)
	if err := cc.Update(bson.M{"_id": bson.ObjectIdHex(pollID)}, &poll); err != nil {
		return c.String(500, "Unable to update poll")
	}
	return c.Redirect(303, fmt.Sprintf("/polls/%s", pollID))
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
	goth.UseProviders(
		twitter.NewAuthenticate(os.Getenv("TWITTER_KEY"), os.Getenv("TWITTER_SECRET"), "http://127.0.0.1:3001/auth/twitter/callback"),
	)
	gothic.Store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
	gothic.GetProviderName = getProvider

	var err error
	session, err = mgo.Dial("mongodb://localhost")
	if err != nil {
		return err
	}
	defer session.Close()
	session.SetMode(mgo.Monotonic, true)
	ensureIndex(session)

	t := &Template{}
	port := c.Int("port")
	e := echo.New()
	e.Use(setUserMiddleware)
	e.Renderer = t
	e.Debug = true
	e.Logger.SetLevel(log.INFO)
	e.GET("/", mainHandler)
	e.GET("/auth/:provider", authTwitterHandler)
	e.GET("/auth/:provider/callback", authTwitterCallbackHandler)
	e.GET("/polls/:id", pollHandler)
	e.POST("/polls/:id", voteHandler)
	e.GET("/polls/:id/delete", deletePollHandler)
	e.GET("/logout", logoutHandler)

	needAuthGroup := e.Group("")
	needAuthGroup.Use(IsAuthMiddleware)
	needAuthGroup.GET("/newpoll", newPollHandler)
	needAuthGroup.POST("/newpoll", createNewPollHandler)
	needAuthGroup.GET("/mypolls", myPollsHandler)
	needAuthGroup.GET("/account", accountHandler)

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
