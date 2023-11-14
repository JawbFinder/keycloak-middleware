package middlewares

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Nerzal/gocloak/v13"
	"github.com/gin-gonic/gin"
)

type Keycloak struct {
	Gocloak      gocloak.GoCloak
	Clientid     string
	ClientSecret string
	Realm        string
}

func NewkeycloakConfidential(KeycloakHost string, ClientId string, ClientSecret string, Realm string) *Keycloak {
	return &Keycloak{Gocloak: *gocloak.NewClient(KeycloakHost), Clientid: ClientId, ClientSecret: ClientSecret, Realm: Realm}

}

func NewkeycloakPublic(KeycloakHost string, ClientId string, Realm string) *Keycloak {
	return &Keycloak{Gocloak: *gocloak.NewClient(KeycloakHost), Clientid: ClientId, Realm: Realm}
}

type KeyCloakMiddleware struct {
	keycloak *Keycloak
}

func newMiddleware(keycloak *Keycloak) *KeyCloakMiddleware {
	return &KeyCloakMiddleware{keycloak: keycloak}
}

func (auth *KeyCloakMiddleware) extractBearerToken(token string) string {
	return strings.Replace(token, "Bearer ", "", 1)
}

func (auth *KeyCloakMiddleware) KeycloakMiddleware() gin.HandlerFunc {

	return func(c *gin.Context) {

		// try to extract Authorization parameter from the HTTP header
		token := c.GetHeader("Authorization")

		if token == "" {
			fmt.Println(c.Params, "Authorization header missing", http.StatusUnauthorized)
			c.AbortWithError(http.StatusUnauthorized, fmt.Errorf("Auth missing"))
			c.JSON(http.StatusBadRequest, gin.H{"message": "Authorization header missing"})
			c.Next()
			return
		}

		// extract Bearer token
		token = auth.extractBearerToken(token)

		if token == "" {
			fmt.Println(c.Params, "Bearer Token missing", http.StatusUnauthorized)
			c.AbortWithError(http.StatusUnauthorized, fmt.Errorf("Bearer Token missing"))
			c.JSON(http.StatusBadRequest, gin.H{"message": "Bearer Token missing"})
			c.Next()
			return
		}

		//// call Keycloak API to verify the access token
		result, err := auth.keycloak.Gocloak.RetrospectToken(context.Background(), token, auth.keycloak.Clientid, auth.keycloak.ClientSecret, auth.keycloak.Realm)
		if err != nil {
			fmt.Println(c.Params, fmt.Sprintf("Invalid or malformed token: %s", err.Error()), http.StatusUnauthorized)
			c.AbortWithError(http.StatusUnauthorized, err)
			c.JSON(http.StatusBadRequest, gin.H{"message": fmt.Sprintf("Invalid or malformed token: %s", err.Error())})
			c.Next()
			return
		}

		jwt, _, err := auth.keycloak.Gocloak.DecodeAccessToken(context.Background(), token, auth.keycloak.Realm)
		if err != nil {
			fmt.Println(c.Params, fmt.Sprintf("Invalid or malformed token: %s", err.Error()), http.StatusUnauthorized)
			c.AbortWithError(http.StatusUnauthorized, err)
			c.JSON(http.StatusBadRequest, gin.H{"message": fmt.Sprintf("Invalid or malformed token: %s", err.Error())})
			c.Next()
			return
		}

		jwtj, _ := json.Marshal(jwt)
		fmt.Printf("token: %v\n", string(jwtj))

		// check if the token isn't expired and valid
		if !*result.Active {
			fmt.Println(c.Params, "Invalid or expired Token", http.StatusUnauthorized)
			c.AbortWithError(http.StatusUnauthorized, fmt.Errorf("Invalid or expired Token"))
			c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid or expired Token"})

			c.Next()
			return
		}
		c.Next()
	}

}

func NewMiddleware(keycloak *Keycloak) *KeyCloakMiddleware {
	return &KeyCloakMiddleware{keycloak: keycloak}
}
