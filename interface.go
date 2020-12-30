package csrf

type TokenGen interface {
	// Validate two tokens
	Validate(storeToken string, inputToken string) bool

	// Get token from Store position, cookies, sessions
	GetStoredToken(storeData string) string

	NewStoreData() string

	// Get token for response to client
	GetToken(storeData string) string
}
