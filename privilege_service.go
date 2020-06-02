package security

type PrivilegeService interface {
	GetPrivilege(userId string, privilegeId string) int32
}
