package main

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"net/http"
)

func mwIsUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		v := session.Get("uid")
		if v != nil && v != "" {
			DD("mwIsUser() Now user logged:v.(int64)= ", v)
			c.Redirect(http.StatusMovedPermanently, "/room/")
			c.Abort()
		}
		c.Next()
	}
}

func mwIsNotUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		v := session.Get("uid")
		if v == "" || v == nil {
			DD("mwIsNotUser() v=empty")
			c.Redirect(http.StatusMovedPermanently, "/auth/login")
			c.Abort()
		}
		c.Next()
	}
}

func confCORS(c *gin.Context) {
	// c.Header("server", WEBSERV_NAME)
	// Content-Security-Policy:
	//     default-src 'self';
	//     connect-src 'self' https://sentry.prod.mozaws.net;
	//     font-src 'self' https://addons.cdn.mozilla.net;
	//     frame-src 'self' https://ic.paypal.com https://paypal.com
	//     img-src 'self' data: blob: https://www.paypal.com https://ssl.google-analytics.com
	//     media-src https://videos.cdn.mozilla.net;
	//     object-src 'none';
	//     script-src 'self' https://addons.mozilla.org
	//     style-src 'self' 'unsafe-inline' https://addons.cdn.mozilla.net;
	//     report-uri /__cspreport__
	h := `
		default-src 'self';
	    connect-src 'self';
	    font-src 'self' blob: https://fonts.gstatic.com;
	    frame-src 'self';
	    img-src 'self' data: blob: 'self';
	    object-src 'self';
	    script-src 'self' 'unsafe-inline' 'unsafe-eval';
	    style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;`
	if gin.Mode() == gin.DebugMode {
		h += `report-uri ` + APP_ENTRYPOINT + `/cspcollector;`
	}
	c.Header("Content-Security-Policy", h)

	if c.Request.Method == "OPTIONS" {
		if len(c.Request.Header["Access-Control-Request-Headers"]) > 0 {
			c.Header("Access-Control-Allow-Headers", c.Request.Header["Access-Control-Request-Headers"][0])
		}
		c.AbortWithStatus(http.StatusOK)
	}
}
