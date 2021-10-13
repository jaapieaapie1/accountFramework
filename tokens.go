package accountFramework

import (
	"github.com/golang-jwt/jwt/v4"
	"time"
)

type NormalClaims struct {
	Uuid int64 `json:"id"`
	Time int64 `json:"time"`
	jwt.RegisteredClaims
}

func GenerateJwt(uuid int64, base []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &NormalClaims{
		Uuid: uuid,
		Time: time.Now().Unix(),
	})

	return token.SignedString(base)
}

func GetJwtContent(jwtToken string, base []byte) (int64, error) {
	token, err := jwt.ParseWithClaims(jwtToken, &NormalClaims{}, func(t *jwt.Token) (interface{}, error) {
		return base, nil
	})

	if err != nil {
		return 0, err
	}

	if claims, ok := token.Claims.(*NormalClaims); ok && token.Valid {
		return claims.Uuid, nil
	} else {
		return 0, err
	}
}
