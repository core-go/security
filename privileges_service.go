package security

import "context"

type PrivilegesLoader interface {
	Privileges(ctx context.Context, userId string) []string
}
