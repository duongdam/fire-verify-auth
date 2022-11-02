## Firebase Middleware Verify Id Token

## Install

```bash
go get github.com/duongdam/fire-verify-auth
```

## Usage

```bash
package firebase_verify_accessToken

import (
	"github.com/gofiber/fiber/v2"
	"os"
	"strings"

	authVerify "github.com/duongdam/fire-verify-auth"
)

type Config struct {
	Key []byte
}

const (
	authorizationHeaderKey  = "authorization"
	authorizationTypeBearer = "bearer"
	userId                  = "user_id"
)

func authMiddleware() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		authorizationHeader := ctx.Get(authorizationHeaderKey)
		fields := strings.Fields(authorizationHeader)
		authorizationType := strings.ToLower(fields[0])
  
		accessToken := fields[1]

		// Verify token
		claims, err := authVerify.VerifyIDToken(accessToken, os.Getenv("GO_PROJECT_ID"))
		if err != nil {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		signInProvider := claims["firebase"].(map[string]interface{})["sign_in_provider"].(string)

		println("signInProvider", signInProvider)

		ctx.Next()
		return nil
	}
}

```