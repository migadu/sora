package server

type User struct {
	Address
	accountID int64
}

func NewUser(address Address, accountID int64) *User {
	return &User{
		Address:   address,
		accountID: accountID,
	}
}

func (u *User) AccountID() int64 {
	return u.accountID
}
