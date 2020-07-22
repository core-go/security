package security

import "context"

type PrivilegeService interface {
	GetPrivilege(ctx context.Context, userId string, privilegeId string) int32
}
