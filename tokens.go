package accountFramework

import (
	"github.com/golang-jwt/jwt/v4"
	"time"
)

type NormalClaims struct {
	Uuid string `json:"uuid"`
	Time int64 `json:"time"`
	jwt.RegisteredClaims
}

func GenerateJwt(uuid string, base []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &NormalClaims{
		Uuid: uuid,
		Time: time.Now().Unix(),
	})

	return token.SignedString(base)
}

func GetJwtContent(jwtToken string, base []byte) (string, error) {
	token, err := jwt.ParseWithClaims(jwtToken, &NormalClaims{},func(t *jwt.Token) (interface{}, error) {
		return base, nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(*NormalClaims); ok && token.Valid {
		return claims.Uuid, nil
	} else {
		return "", err
	}
}