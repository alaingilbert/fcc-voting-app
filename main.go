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
var authTokenCookieName = "auth-token"

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
	ID                 bson.ObjectId `bson:"_id"`
	NickName           string
	TwitterID          string
	SessionKey         string
	TwitterAccessToken string
	TwitterAvatarURL   string
	Name               string
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
	if err := c.Find(bson.M{}).All(&polls); err != nil {
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
	pollsCollection := s.DB("poll").C("polls")
	err := pollsCollection.Insert(poll)
	if err != nil {
		return err
	}
	return c.Redirect(303, fmt.Sprintf("/polls/%s", poll.ID.Hex()))
}

func NewUserFromGothUser(gothUser goth.User) *User {
	u := new(User)
	u.ID = bson.NewObjectId()
	u.NickName = gothUser.NickName
	u.TwitterID = gothUser.UserID
	u.SessionKey = ""
	u.TwitterAccessToken = gothUser.AccessToken
	u.TwitterAvatarURL = gothUser.AvatarURL
	u.Name = gothUser.Name
	return u
}

func GenerateToken() string {
	// This error can safely be ignored.
	// Only crash when year is outside of [0,9999]
	key, _ := time.Now().MarshalText()
	token := hex.EncodeToString(hmac.New(sha256.New, key).Sum(nil))
	return token
}

func SetUserAuthToken(gothUser goth.User, token string) error {
	s := session.Copy()
	defer s.Close()
	usersCollection := s.DB("poll").C("users")
	if err := usersCollection.Update(bson.M{"twitterid": gothUser.UserID}, bson.M{"$set": bson.M{"sessionkey": token}}); err != nil {
		u := NewUserFromGothUser(gothUser)
		u.SessionKey = token
		if err := usersCollection.Insert(*u); err != nil {
			if !mgo.IsDup(err) {
				return err
			}
		}
	}
	return nil
}

func authTwitterHandler(c echo.Context) error {
	// try to get the user without re-authenticating
	res := c.Response()
	req := c.Request()
	if gothUser, err := gothic.CompleteUserAuth(res, req); err == nil {
		token := GenerateToken()
		if err := SetUserAuthToken(gothUser, token); err != nil {
			return err
		}
		cookie := http.Cookie{Name: authTokenCookieName, Value: token, Path: "/"}
		c.SetCookie(&cookie)
		return c.Redirect(303, "/")
	} else {
		gothic.BeginAuthHandler(res, req)
		return nil
	}
}

func authTwitterCallbackHandler(c echo.Context) error {
	gothUser, err := gothic.CompleteUserAuth(c.Response(), c.Request())
	if err != nil {
		return err
	}
	token := GenerateToken()
	if err := SetUserAuthToken(gothUser, token); err != nil {
		return err
	}
	cookie := http.Cookie{Name: authTokenCookieName, Value: token, Path: "/"}
	c.SetCookie(&cookie)
	return c.Redirect(303, "/")
}

func logoutHandler(c echo.Context) error {
	//cookie1 := &http.Cookie{
	//	Name:   fmt.Sprintf("twitter%s", gothic.SessionName),
	//	Value:  "",
	//	Path:   "/",
	//	MaxAge: -1,
	//}
	//c.SetCookie(&cookie1)
	cookie := http.Cookie{Name: authTokenCookieName, Value: "", Path: "/"}
	c.SetCookie(&cookie)
	return c.Redirect(302, "/")
}

func accountHandler(c echo.Context) error {
	data := H{"user": c.Get("user")}
	return c.Render(200, "user", data)
}

func getVotesAggrForPoll(pollID string) ([]bson.M, error) {
	s := session.Copy()
	defer s.Close()
	pollsCollection := s.DB("poll").C("polls")
	match := bson.M{"$match": bson.M{"_id": bson.ObjectIdHex(pollID)}}
	project := bson.M{"$project": bson.M{"votes": 1}}
	unwind := bson.M{"$unwind": "$votes"}
	group := bson.M{"$group": bson.M{"_id": "$votes.choice", "count": bson.M{"$sum": 1}}}
	pipe := pollsCollection.Pipe([]bson.M{match, project, unwind, group})
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
	pollsCollection := s.DB("poll").C("polls")
	var poll Poll
	if err := pollsCollection.Find(bson.M{"_id": bson.ObjectIdHex(pollID)}).One(&poll); err != nil {
		return c.Redirect(302, "/")
	}
	data := H{"user": user, "poll": poll}
	alreadyVoted := hasUserVotedOnPoll(user.TwitterID, ip, pollID)
	data["already_voted"] = alreadyVoted
	if alreadyVoted {
		aggr, _ := getVotesAggrForPoll(pollID)
		data["aggr"] = aggr
	}
	return c.Render(200, "poll", data)
}

func myPollsHandler(c echo.Context) error {
	user := c.Get("user").(User)
	s := session.Copy()
	defer s.Close()
	pollsCollection := s.DB("poll").C("polls")
	var polls []Poll
	err := pollsCollection.Find(bson.M{"author": user.TwitterID}).All(&polls)
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
	pollsCollection := s.DB("poll").C("polls")
	if err := pollsCollection.Remove(bson.M{"_id": bson.ObjectIdHex(c.Param("id")), "author": user.TwitterID}); err != nil {
		fmt.Println(err)
		return c.Redirect(302, "/mypolls")
	}
	return c.Redirect(302, "/mypolls")
}

func hasUserVotedOnPoll(userID, IP, pollID string) bool {
	s := session.Copy()
	defer s.Close()
	pollsCollection := s.DB("poll").C("polls")
	err := pollsCollection.Find(bson.M{
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
	pollsCollection := s.DB("poll").C("polls")

	if hasUserVotedOnPoll(user.TwitterID, ip, pollID) {
		return c.String(400, "You can't vote twice")
	}

	var poll Poll
	if err := pollsCollection.Find(bson.M{"_id": bson.ObjectIdHex(pollID)}).One(&poll); err != nil {
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
			data := H{"user": user, "poll": poll, "error": "You have to be authenticated to create a new choice"}
			return c.Render(200, "poll", data)
		}
		newChoice := strings.Trim(c.FormValue("other_choice"), " \n\r\t")
		if newChoice == "" {
			data := H{"user": user, "poll": poll, "error": "You cannot leave en empty vote"}
			return c.Render(200, "poll", data)
		}
		if !inArray(newChoice, poll.Answers) {
			poll.Answers = append(poll.Answers, newChoice)
		}
		vote.Choice = newChoice
	} else {
		vote.Choice = choice
	}
	poll.Votes = append(poll.Votes, vote)
	if err := pollsCollection.Update(bson.M{"_id": bson.ObjectIdHex(pollID)}, &poll); err != nil {
		return c.String(500, "Unable to update poll")
	}
	return c.Redirect(303, fmt.Sprintf("/polls/%s", pollID))
}

func ensureIndex() {
	s := session.Copy()
	defer s.Close()
	c := s.DB("poll").C("users")
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

// IsAuthMiddleware will ensure user is authenticated.
// - Find user from context
// - If user is empty, redirect to home
func IsAuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		user := c.Get("user").(User)
		if user.TwitterID == "" {
			return c.Redirect(302, "/")
		}
		return next(c)
	}
}

// SetUserMiddleware Get user and put it into echo context.
// - Get auth-token from cookie
// - If exists, get user from database
// - If found, set user in echo context
// - Otherwise, empty user will be put in context
func SetUserMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		var user User
		authCookie, err := c.Cookie(authTokenCookieName)
		if err != nil {
			c.Set("user", user)
			return next(c)
		}
		s := session.Copy()
		defer s.Close()
		usersCollection := s.DB("poll").C("users")
		if err := usersCollection.Find(bson.M{"sessionkey": authCookie.Value}).One(&user); err != nil {
		}
		c.Set("user", user)
		return next(c)
	}
}

func getProvider(req *http.Request) (string, error) {
	return "twitter", nil
}

func start(c *cli.Context) error {
	goth.UseProviders(
		twitter.NewAuthenticate(os.Getenv("TWITTER_KEY"), os.Getenv("TWITTER_SECRET"), os.Getenv("TWITTER_CALLBACK")),
	)
	gothic.Store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
	gothic.GetProviderName = getProvider

	var err error
	session, err = mgo.Dial(os.Getenv("MONGODB_URI"))
	if err != nil {
		return err
	}
	defer session.Close()
	session.SetMode(mgo.Monotonic, true)
	ensureIndex()

	t := &Template{}
	port := c.Int("port")
	e := echo.New()
	e.Use(SetUserMiddleware)
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
	app.Name = "FCC voting app"
	app.Usage = "FCC voting app"
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
