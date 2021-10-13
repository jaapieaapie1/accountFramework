package accountFramework

import (
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

func (i Instance) HandlePostRegisterRequest(w http.ResponseWriter, r *http.Request) {
	username := r.PostFormValue("username")
	email := r.PostFormValue("email")
	password := r.PostFormValue("password")

	u := uuid.New()

	stmt, err := i.DBConnection.Prepare("INSERT INTO user (uuid, username, email, password) VALUES (?, ?, ?, ?);")

	hash, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(500)
		return
	}

	_, err = stmt.Exec(u, username, email, hash)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(500)
		return
	}

	jw, err := GenerateJwt(u.String(), i.JWTBase)

	if err != nil {
		fmt.Println(err)
		w.WriteHeader(500)
		return
	}

	r.AddCookie(&http.Cookie{
		Name: "Authorization",
		Value: jw,
	})
}

func (i Instance) HandlePostLoginRequest(w http.ResponseWriter, r *http.Request) {
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	stmt, err := i.DBConnection.Prepare("SELECT uuid, password FROM user WHERE username = ? OR password = ? LIMIT 1;")

	if err != nil {
		fmt.Println(err)
		w.WriteHeader(500)
		return
	}

	rows, err := stmt.Query(username, username)

	if err != nil {
		fmt.Println(err)
		w.WriteHeader(500)
		return
	}

	if rows.Next() {
		var uuidString string
		var passwordHash string

		err = rows.Scan(&uuidString, &passwordHash)

		if !CheckPasswordHash(password, passwordHash) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"uuid" : uuidString,
			"time": time.Now().Unix(),
		})

		signed, err := token.SignedString(i.JWTBase)

		if err != nil {
			w.WriteHeader(500)
			return
		}

		r.AddCookie(&http.Cookie{
			Name: "Authorization",
			Value: signed,
		})
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(500)
			return
		}
	}

	w.WriteHeader(http.StatusNotFound)
	return

}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}