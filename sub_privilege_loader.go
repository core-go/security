package security

import "context"

type SubPrivilegeLoader interface {
	Privilege(ctx context.Context, userId string, privilegeId string, sub string) int32
}
