package csrf

type TokenGen interface {
	Validate(storeToken string, inputToken string) bool
	GetStoreToken(storeSalt string) string
	GetSecret() string
	NewStoreData() string
}
