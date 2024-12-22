package server

type User struct {
	Address
	userID int
}

func NewUser(address Address, userID int) *User {
	return &User{
		Address: address,
		userID:  userID,
	}
}

func (u *User) UserID() int {
	return u.userID
}
