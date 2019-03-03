package types

// AuthArgs contains AppKey authentication parameters.
type AuthArgs struct {
	AppID     string `validate:"required"`
	AppKey    string `validate:"required"`
	AppTenant string `validate:"required"`
}
