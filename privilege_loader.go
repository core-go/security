package security

import "context"

type PrivilegeLoader interface {
	Privilege(ctx context.Context, userId string, privilegeId string) int32
}
