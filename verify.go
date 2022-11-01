package fire_verify_auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"

	jwtGo "github.com/dgrijalva/jwt-go"
)

const (
	clientCertURL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
)

func VerifyIDToken(idToken string, projectID string) (map[string]interface{}, error) {
	keys, err := fetchPublicKeys()

	if err != nil {
		return nil, err
	}

	parsedToken, parseErr := jwtGo.Parse(idToken, func(token *jwtGo.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwtGo.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid := token.Header["kid"]
		rsaPublicKey := convertKey(string(*keys[kid.(string)]))
		return rsaPublicKey, nil
	})

	if parseErr != nil {
		return nil, parseErr
	}

	if parsedToken == nil {
		return nil, errors.New("nil parsed token")
	}

	errMessage := ""
	claims, ok := parsedToken.Claims.(jwtGo.MapClaims)

	if ok && parsedToken.Valid {
		if claims["aud"].(string) != projectID {
			errMessage = "Firebase Auth ID token has incorrect 'aud' claim: " + claims["aud"].(string)
		} else if claims["iss"].(string) != "https://securetoken.google.com/"+projectID {
			errMessage = "Firebase Auth ID token has incorrect 'iss' claim"
		} else if claims["sub"].(string) == "" || len(claims["sub"].(string)) > 128 {
			errMessage = "Firebase Auth ID token has invalid 'sub' claim"
		}
	}

	if errMessage != "" {
		return nil, errors.New(errMessage)
	}

	return claims, nil
}

func fetchPublicKeys() (map[string]*json.RawMessage, error) {
	resp, err := http.Get(clientCertURL)
	if err != nil {
		return nil, err
	}

	var objMap map[string]*json.RawMessage
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&objMap)

	return objMap, err
}

func convertKey(key string) interface{} {
	certPEM := key
	certPEM = strings.Replace(certPEM, "\\n", "\n", -1)
	certPEM = strings.Replace(certPEM, "\"", "", -1)
	block, _ := pem.Decode([]byte(certPEM))
	cert, _ := x509.ParseCertificate(block.Bytes)
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)

	return rsaPublicKey
}
