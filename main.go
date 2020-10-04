package main

import (
	// "encoding/json"
	"fmt"
	"log"
	"os"
	"io"
	serpapi "my.localhost/funny/activeseo/services/dataforseo"
	// "strings"
	"regexp"
	"github.com/cnjack/throttle"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"net/http"
	// "strconv"
	"time"
)

var (
	KEY32                string
	LOGS_PATH            string
	SSLKEYS_PATH         string
	WEBSERV_NAME         string
	STORAGE_DRV          string
	STORAGE_DSN          string
	APP_ENTRYPOINT       string
	APP_BRANDNAME        string
	APP_FQDN             string
	APP_FQDN_ADDITIONAL  string
	APP_FQDN_ADDITIONAL2 string
	APP_SSL_ENTRYPOINT   string
	SERPAPI_LOCATIONS_URL  string
	SERPAPI_LANGS_URL      string
	SERPAPI_UDATA_URL      string
	SERPAPI_SETUPSEOTASK_URL string
	SERPAPI_GETRESULT_URL  string
)
type (
	// PageData struct {
	// 	Title             string
	// 	Lang             string
	// 	BaseUrl          string
	// 	Data             interface{}
	// }
)

func init() {
	err := godotenv.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Problem with db connection: %s\n", err)
		os.Exit(1)
	}

	gin.SetMode(os.Getenv("GIN_MODE"))
	APP_BRANDNAME = os.Getenv("app_brandname")
	APP_FQDN = os.Getenv("app_fqdn")
	APP_FQDN_ADDITIONAL = os.Getenv("app_fqdn_additional")
	APP_FQDN_ADDITIONAL2 = os.Getenv("app_fqdn_additional2")
	LOGS_PATH = os.Getenv("logs_path")
	WEBSERV_NAME = os.Getenv("webserv_name")
	SSLKEYS_PATH = os.Getenv("sslkeys_path")
	APP_ENTRYPOINT = os.Getenv("app_entrypoint")
	APP_SSL_ENTRYPOINT = os.Getenv("app_ssl_entrypoint")
	STORAGE_DRV = os.Getenv("db_type")
	STORAGE_DSN = os.Getenv("db_user") + ":" + os.Getenv("db_pass") + "@tcp(" + os.Getenv("db_host") + ":" + os.Getenv("db_port") + ")/" + os.Getenv("db_name") + "?parseTime=true"
	KEY32 = os.Getenv("app_secret_key")
	
	SERPAPI_LOCATIONS_URL=os.Getenv("SERPAPI_LOCATIONS_URL")
	SERPAPI_LANGS_URL=os.Getenv("SERPAPI_LANGS_URL")
	SERPAPI_UDATA_URL=os.Getenv("SERPAPI_UDATA_URL")
	SERPAPI_SETUPSEOTASK_URL=os.Getenv("SERPAPI_SETUPSEOTASK_URL")
	SERPAPI_GETRESULT_URL=os.Getenv("SERPAPI_GETRESULT_URL")
}

func main() {
	router := gin.New()

	// Define common middlewares
	router.Use(gin.Recovery())
	router.Use(confCORS)

	if gin.Mode() == gin.ReleaseMode {
		gin.DisableConsoleColor()
		// Sett log format:
		f, _ := os.Create(LOGS_PATH)
		gin.DefaultWriter = io.MultiWriter(f)
		fmt.Println("DEBUG MODE: ", gin.IsDebugging())
		fmt.Println("LOGING MODE: Enabled (logs, console, debug messages)")
		router.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
			//custom format for logging:
			return fmt.Sprintf("%s - [%s] %s \"%s\" %d \"%s\" %s\n",
				param.TimeStamp.Format("2006-01-02 15:04:05"),
				param.ClientIP,
				param.Method,
				param.Path,
				param.StatusCode,
				param.Request.UserAgent(),
				param.ErrorMessage,
			)
		}))
	} else {
		fmt.Println("DEBUG MODE:gin.Mode():", gin.Mode(), " gin.IsDebugging()=", gin.IsDebugging())
	}

	// Server settings
	router.Delims("{*", "*}")
	router.LoadHTMLGlob("./templates/*.htmlt")
	router.MaxMultipartMemory = 32 << 20 // 8 MiB
	s := &http.Server{
		Handler:        router,
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   15 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 8 << 20,
	}

	// Session store init
	sessionStore := cookie.NewStore([]byte("secretu"), []byte(KEY32))
	router.Use(sessions.Sessions("bin", sessionStore)) //Название ключа в куках

	router.Static("/assets", "./assets")
	router.StaticFile("/favicon.ico", "./assets/img/favicons/favicon.png")

	// Service routes
	router.POST("/cspcollector", func(c *gin.Context) {
		cspdata, err := c.GetRawData()
		if err != nil {
			fmt.Println("SCP report error")
		}
		DD("ContentSecurePolicy:", string(cspdata))
	})

	// router.GET("/pubsub", func(c *gin.Context) {
	// 	redisParam := storage.NewInput{
	// 		RedisURL: "127.0.0.1:6379",
	// 	}
	// 	rdPool := storage.NewPubsub(redisParam)
	// 	_ = rdPool.Publish(key string, value string)

	// 	// Subscribe subscribe
	// 	_ = rdPool.Subscribe(key string, msg chan []byte)

	// 	c.String(http.StatusOK, "welcome to pubsub")
	// })

// Первая страница.
	router.GET("/", func(c *gin.Context) {
		uid, _ := getSessionCredentials(c)
		c.HTML(http.StatusOK, "welcome.htmlt", gin.H{
			"title":"Welcome",
			"brandname":APP_BRANDNAME,
			"uid":uid,
		})
	})

	auth := router.Group("/auth", mwIsUser(), throttle.Policy(&throttle.Quota{
		Limit:  4,
		Within: time.Minute,
	}))

	auth.GET("/login", func(c *gin.Context) {
		uid, _ := getSessionCredentials(c)
		c.HTML(http.StatusOK, "auth.login.htmlt", gin.H{
			"title":"Welcome",
			"brandname":APP_BRANDNAME,
			"uid":uid,
		})
	})

	router.GET("/403", func(c *gin.Context) {
		c.HTML(http.StatusOK, "403.htmlt", gin.H{
			"title":"Forbidden 403",
			"brandname":APP_BRANDNAME,
		})
	})

	router.GET("/404", func(c *gin.Context) {
		c.HTML(http.StatusNotFound, "404.htmlt", gin.H{
			"title":"NotFound 404",
			"brandname":APP_BRANDNAME,
		})
	})


	auth.POST("/login", func(c *gin.Context) {
		email := c.PostForm("email")
		password := c.PostForm("password")
		
		//validation
		var validEmailPattern = regexp.MustCompile(`^[_a-zA-Z0-9]{2,60}@[a-zA-Z0-9]{2,56}.[a-zA-Z]{2,6}$`)
		if ok := validEmailPattern.MatchString(email); !ok {
			c.JSON(http.StatusBadRequest, gin.H{"warn": "invalid email address"})
			return
		}
		var validPasswordPattern = regexp.MustCompile(`^[a-zA-Z0-9]{10,40}$`)
		if ok := validPasswordPattern.MatchString(password); !ok {
			c.JSON(http.StatusBadRequest, gin.H{"warn": "invalid password"})
			return
		}
		
		// Проверяем наличие uid в сессии
		var uid, code, errMsg string
		uid, _ = getSessionCredentials(c)
		
		if uid == "" {
			creds := serpapi.ServiceSerpApiCred{
				Login: email, 
				Password: password,
			} 
			
			// Запрашиваем у серпапи инфу о пользователе
			uid, code, errMsg = serpapi.RetrieveUserInfo(creds, SERPAPI_UDATA_URL) 
			if uid != email {
				c.JSON(http.StatusBadRequest, gin.H{
					"code": code,
					"warn": errMsg,
				})
				return
			}

			DD("DEBUG:email=", email) // challenger16@rankactive.info
			DD("DEBUG:u=", uid) // challenger16@rankactive.info
			DD("DEBUG:errmsg=", errMsg)
			DD("DEBUG:code=", code)

			setSessionCredentials(c, email, password)
		}
		c.Redirect(http.StatusMovedPermanently, "/room/")
	})

	room := router.Group("/room", mwIsNotUser(), throttle.Policy(&throttle.Quota{
		Limit:  10,
		Within: time.Minute,
	}))
	
	// Пользователь (авторизовавшись):
	// - выбирает поисковую систему
	// - выбирает регион поиска (Можете сделать регионы Соединенных Штатов Америки или на ваше усмотрение, не принципиально)
	// - вводит ключевое слово
	room.GET("/", func(c *gin.Context) {
		uid, _ := getSessionCredentials(c)
		DD("/room/ uid:",uid)
		c.HTML(http.StatusOK, "taskform.htmlt", gin.H{
			"title" :"Set seotask",
			"brandname" :APP_BRANDNAME,
			"uid": uid,
		})
	})

	room.POST("/seotask", func(c *gin.Context) {
		_ = c.PostForm("_token")
		se := c.PostForm("search_engine")
		country_id := c.PostForm("country_id")
		region_id := c.PostForm("region_id")
		keywords := c.PostForm("keywords")

		//validation
		var validSePattern = regexp.MustCompile(`^google|yandex|bing|yahoo$`)
		if ok := validSePattern.MatchString(se); !ok {
			c.JSON(http.StatusBadRequest, gin.H{"warn": "invalid search_engine"})
			return
		}
		var validPasswordPattern = regexp.MustCompile(`^[0-9]{1,4}$`)
		if ok := validPasswordPattern.MatchString(country_id); !ok {
			c.JSON(http.StatusBadRequest, gin.H{"warn": "invalid country_id parameter"})
			return
		}
		var validLocationIdPattern = regexp.MustCompile(`^[0-9]{1,4}$`)
		if ok := validLocationIdPattern.MatchString(region_id); !ok {
			c.JSON(http.StatusBadRequest, gin.H{"warn": "invalid region_id parameter"})
			return
		}
		var validKeywordsPattern = regexp.MustCompile(`^[\s\_\-a-zA-Z0-9]{3,64}$`)
		DD("keywordsRaw:",keywords)
		if ok := validKeywordsPattern.MatchString(keywords); !ok {
			c.JSON(http.StatusBadRequest, gin.H{"warn": "invalid keywords field"})
			return
		}
		
		// отправляет запрос на постановку задачи (
		// AJAX-запросом вызывается PHP-скрипт, 
		// который отправляет/получает данные от API-сервера:
		// - сохраняет задачу в очередь редиса,
		// - сохраняет ответ от постановки задачи в БД,
		
		// Проверяем наличие uid, password в сессии
		var uid, code, errMsg string
		uid, password := getSessionCredentials(c)
		
		if uid == ""  || password == "" {
			c.JSON(http.StatusInternalServerError, gin.H{
				"code": code,
				"warn": errMsg,
			})
			return
		}
		serpapiCreds := serpapi.ServiceSerpApiCred{
			Login: uid, 
			Password: password,
		} 
		
		// taskId, statusMsg, statusCode, tasksErr = serpapi.SetupSeotask(serpapiCreds, SERPAPI_UDATA_URL) 
		_,_,tasksErr := serpapi.SetupSeotask(serpapiCreds, SERPAPI_SETUPSEOTASK_URL, se, region_id, keywords) 
		if tasksErr != "0" {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"code": code,
				"warn": errMsg,
			})
			return
		}

		c.Redirect(http.StatusMovedPermanently, "/room/tasks")
	})


// Вторая страница.
// Отображение статуса поставленных задач, в задачу можна зайти и посмотреть результат.
// [ ] /room/tasks GET
	room.GET("/tasks", func(c *gin.Context) {
		uid, _ := getSessionCredentials(c)
		DD("/tasks uid:",uid)
		c.HTML(http.StatusOK, "taskslist.htmlt", gin.H{
			"title" :"Seotask list",
			"brandname" :APP_BRANDNAME,
			"uid": uid,
		})
	})
	
	// Start server
	s.Addr = APP_ENTRYPOINT
	DD("DEVELOPER SERVER MODE: without https")
	err := s.ListenAndServe()
	if err != nil {
		log.Fatalf("ListenAndServe error: %v", err)
	}
}
