package csrf

import (
	"errors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const (
	csrfStoreData = "csrfStoreData"
	csrfToken     = "csrfToken"
)

var defaultIgnoreMethods = []string{"GET", "HEAD", "OPTIONS"}

var defaultErrorFunc = func(c *gin.Context) {
	panic(errors.New("CSRF token mismatch"))
}

var defaultTokenGetter = func(c *gin.Context) string {
	r := c.Request

	if t := r.FormValue("_csrf"); len(t) > 0 {
		return t
	} else if t := r.URL.Query().Get("_csrf"); len(t) > 0 {
		return t
	} else if t := r.Header.Get("X-CSRF-TOKEN"); len(t) > 0 {
		return t
	} else if t := r.Header.Get("X-XSRF-TOKEN"); len(t) > 0 {
		return t
	}

	return ""
}

// Options stores configurations for a CSRF middleware.
type Options struct {
	Secret        string
	IgnoreMethods []string
	ErrorFunc     gin.HandlerFunc
	TokenGetter   func(c *gin.Context) string
	TokenGen      TokenGen
}

func inArray(arr []string, value string) bool {
	inarr := false

	for _, v := range arr {
		if v == value {
			inarr = true
			break
		}
	}

	return inarr
}

// Middleware validates CSRF token.
func Middleware(options Options) gin.HandlerFunc {
	ignoreMethods := options.IgnoreMethods
	errorFunc := options.ErrorFunc
	tokenGetter := options.TokenGetter
	tokenGen := options.TokenGen

	if ignoreMethods == nil {
		ignoreMethods = defaultIgnoreMethods
	}

	if errorFunc == nil {
		errorFunc = defaultErrorFunc
	}

	if tokenGetter == nil {
		tokenGetter = defaultTokenGetter
	}

	if tokenGen == nil {
		tokenGen = NewDefaultTokenGen(options.Secret)
	}

	return func(c *gin.Context) {
		c.Set("tokenGen", tokenGen)

		if inArray(ignoreMethods, c.Request.Method) {
			c.Next()
			return
		}

		session := sessions.Default(c)
		storeData, ok := session.Get(csrfStoreData).(string)

		if !ok || len(storeData) == 0 {
			errorFunc(c)
			return
		}
		inputToken := tokenGetter(c)
		storeToken := tokenGen.GetStoreToken(storeData)
		if tokenGen.Validate(storeToken, inputToken) {
			errorFunc(c)
			return
		}

		c.Next()
	}
}

// GetToken returns a CSRF token.
func GetToken(c *gin.Context) string {
	session := sessions.Default(c)
	tokenGen := c.MustGet("tokenGen").(TokenGen)

	if t, ok := c.Get(csrfToken); ok {
		return t.(string)
	}

	storeData, ok := session.Get(csrfStoreData).(string)
	if !ok {
		storeData = tokenGen.NewStoreData()
		session.Set(csrfStoreData, storeData)
		_ = session.Save()
	}
	token := tokenGen.GetStoreToken(storeData)
	c.Set(csrfToken, token)

	return token
}
