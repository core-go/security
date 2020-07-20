package security

type PrivilegeService interface {
	GetPrivilege(userId string, privilegeId string) int32
	GetPrivileges(userId string) []string
}
