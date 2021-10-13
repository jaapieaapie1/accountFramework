package accountFramework

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"testing"
)

var base = []byte("abcdefghijklmnop")
var testUuid = "32c71380-d71d-42f8-84bc-17a0cbd4618e"
var testJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1dWlkIjoiMzJjNzEzODAtZDcxZC00MmY4LTg0YmMtMTdhMGNiZDQ2MThlIiwidGltZSI6MTYzNDEwODAxOH0.pW2qZ6rCHWmwJYfFqnZqndYnZOzoP9V1zD0u11HdA-M"
var testPassword = "Welcome123"


func TestGetJwtContent(t *testing.T) {
	uuid, err := GetJwtContent(testJwt, base)

	if err != nil {
		t.Fail()
		return
	}
	if uuid != testUuid {
		t.Fail()
		return
	}
}

func TestGeneratingJwt(t *testing.T) {
	jwt, err := GenerateJwt(testUuid, base)
	if err != nil {
		t.Fail()
		return
	}

	uuid, err := GetJwtContent(jwt, base)

	if uuid != testUuid {
		t.Fail()
		return
	}

}

func TestCheckPasswordHash(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), 14)

	if err != nil {
		fmt.Println(err)
		t.Fail()
		return
	}

	err = bcrypt.CompareHashAndPassword(hash, []byte(testPassword))
	if err != nil {
		fmt.Println(err)
		t.Fail()
		return
	}
}