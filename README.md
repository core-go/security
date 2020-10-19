# Gin Security 
AuthenticationHandler
- Implementation of TokenVerifier: [DefaultTokenService](https://github.com/common-go/jwt/blob/master/default_token_service.go) of [common-go/jwt](https://github.com/common-go/jwt) v0.0.7 or above
- Implementation of CacheService: [RedisService](https://github.com/common-go/redis/blob/master/redis_service.go) of [common-go/redis](https://github.com/common-go/redis) v1.0.0 or above

## Installation

Please make sure to initialize a Go module before installing common-go/web-security:

```shell
go get -u github.com/common-go/web-security
```

Import:

```go
import "github.com/common-go/web-security"
```

#### You can optimize the import by version:
##### v0.0.1: Authentication Handler
##### v0.0.5: Authorizer
##### v0.0.7: Token Authorizer
- Privilege Authorizer
- Role Authorizer
- User Authorizer
- User Type Authorizer
