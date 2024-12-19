package server

type SoraUser struct {
	address Address
	userID  int
}

func (u *SoraUser) Address() string {
	return u.address.Address
}

func (u *SoraUser) LocalPart() string {
	return u.address.LocalPart
}

func (u *SoraUser) Domain() string {
	return u.address.Domain
}

func (u *SoraUser) UserID() int {
	return u.userID
}

func NewSoraUser(address Address, userID int) *SoraUser {
	return &SoraUser{
		address: address,
		userID:  userID,
	}
}
