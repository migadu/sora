package server

type SoraUser struct {
	address   string
	localPart string
	domain    string
	userID    int
}

func (u *SoraUser) Address() string {
	return u.address
}

func (u *SoraUser) LocalPart() string {
	return u.localPart
}

func (u *SoraUser) Domain() string {
	return u.domain
}
