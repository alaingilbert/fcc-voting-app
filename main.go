package main

import (
	"fmt"
	"github.com/labstack/echo"
	"github.com/urfave/cli"
	"os"
)

type H map[string]interface{}

func mainHandler(c echo.Context) error {
	return c.String(200, "Hello World")
}

func start(c *cli.Context) error {
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
