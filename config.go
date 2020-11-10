package security

type SecurityConfig struct {
	SecuritySkip         bool
	AuthorizationChecker AuthorizationChecker
	ExactAuthorizer      Authorizer
	Authorizer           Authorizer
	SubAuthorizer        SubAuthorizer
	ArrayAuthorizer      ArrayAuthorizer
}
