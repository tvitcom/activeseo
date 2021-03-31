package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"strings"
)

//TODO : make normal getting browser lang
func GetBrowserLang() string {
	return "en"
}

func MakeNameFromEmail(email string) string {
	str := strings.Split(email, string('@'))
	return str[0]
}

// print debug indormation only if debug mode available
func DD(args ...interface{}) {
	debugee := []interface{}{0: "DEBUG:"}
	args = append(debugee, args)
	if gin.IsDebugging() {
		fmt.Println(args...)
	}
}
