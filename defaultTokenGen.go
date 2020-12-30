package csrf

import (
	"crypto/sha1"
	"encoding/base64"
	"github.com/dchest/uniuri"
	"io"
)

type DefaultTokenGen struct {
	Secret string
}

func (g *DefaultTokenGen) GetStoredToken(storeData string) string {
	return tokenize(g.Secret, storeData)
}

func (g *DefaultTokenGen) GetToken(storeData string) string {
	return tokenize(g.Secret, storeData)
}

func NewDefaultTokenGen(secret string) *DefaultTokenGen {
	return &DefaultTokenGen{Secret: secret}
}

func (g *DefaultTokenGen) Validate(storeToken string, inputToken string) bool {
	return storeToken != inputToken
}

func tokenize(secret, salt string) string {
	h := sha1.New()
	_, _ = io.WriteString(h, salt+"-"+secret)
	hash := base64.URLEncoding.EncodeToString(h.Sum(nil))

	return hash
}

func (g *DefaultTokenGen) NewStoreData() string {
	return g.getNewSalt()
}

func (g *DefaultTokenGen) getNewSalt() string {
	return uniuri.New()
}
