package main

type (
	User struct {
		Login string
		Password string
	}
)

func GetUserInfo(id int64) User {
	_ = id
	return User{
		Login:    "123",
		Password: "456",
	}
}
