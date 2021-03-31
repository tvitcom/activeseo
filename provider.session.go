package main

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func getSessionCredentials(c *gin.Context) (uid, password string) {
	session := sessions.Default(c)
	id := session.Get("uid")
	pass := session.Get("password")
	uid, ok_uid := id.(string)
	password, ok_pass := pass.(string)
	if !ok_uid || !ok_pass {
		return "", ""
	}
	return uid, password
}

func setSessionCredentials(c *gin.Context, uid, password string) {
	session := sessions.Default(c)
	session.Set("uid", uid)
	session.Save()
	session.Set("password", password)
	session.Save()
}

func clearSession(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
}
