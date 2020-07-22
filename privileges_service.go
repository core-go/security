package security

import "context"

type PrivilegesService interface {
	GetPrivileges(ctx context.Context, userId string) []string
}
