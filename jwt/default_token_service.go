package jwt

type DefaultTokenService struct {
}

func NewTokenService() *DefaultTokenService {
	return &DefaultTokenService{}
}
func (t *DefaultTokenService) GenerateToken(payload interface{}, secret string, expiresIn int64) (string, error) {
	return GenerateToken(payload, secret, expiresIn)
}

func (t *DefaultTokenService) VerifyToken(tokenString string, secret string) (map[string]interface{}, int64, int64, error) {
	payload, c, err := VerifyToken(tokenString, secret)
	return payload, c.IssuedAt, c.ExpiresAt, err
}
