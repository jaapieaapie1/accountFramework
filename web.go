package accountFramework

import (
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

func (i Instance) HandlePostRegisterRequest(w http.ResponseWriter, r *http.Request) {
	username := r.PostFormValue("username")
	email := r.PostFormValue("email")
	password := r.PostFormValue("password")

	u := i.snowFlakeNode.Generate()

	stmt, err := i.DBConnection.Prepare("INSERT INTO user (id, username, email, password) VALUES (?, ?, ?, ?);")

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

	jw, err := GenerateJwt(u.Int64(), i.JWTBase)

	if err != nil {
		fmt.Println(err)
		w.WriteHeader(500)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "Authorization",
		Value: jw,
	})
}

func (i Instance) HandlePostLoginRequest(w http.ResponseWriter, r *http.Request) {
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	stmt, err := i.DBConnection.Prepare("SELECT id, password FROM user WHERE username = ? OR password = ? LIMIT 1;")

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
		var id int64
		var passwordHash string

		err = rows.Scan(&id, &passwordHash)

		if !CheckPasswordHash(password, passwordHash) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"id":   id,
			"time": time.Now().Unix(),
		})

		signed, err := token.SignedString(i.JWTBase)

		if err != nil {
			w.WriteHeader(500)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:  "Authorization",
			Value: signed,
		})
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(500)
			return
		}
		return
	}

	w.WriteHeader(http.StatusNotFound)
	return

}

func (i Instance) CheckRequest(r *http.Request) (bool, int64) {
	cookie, err := r.Cookie("Authorization")

	if err != nil {
		return false, 0
	}

	uuid, err := GetJwtContent(cookie.Value, i.JWTBase)

	if err != nil {
		return false, 0
	}

	return true, uuid
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
