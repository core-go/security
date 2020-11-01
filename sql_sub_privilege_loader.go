package security

import (
	"context"
	"database/sql"
)

type SqlSubPrivilegeLoader struct {
	DB    *sql.DB
	Query string
}

func NewSqlSubPrivilegeLoader(db *sql.DB, query string) *SqlSubPrivilegeLoader {
	return &SqlSubPrivilegeLoader{DB: db, Query: query}
}
func (l SqlSubPrivilegeLoader) Privilege(ctx context.Context, userId string, privilegeId string, sub string) int32 {
	var permissions int32 = 0
	err := l.DB.QueryRow(l.Query, userId, privilegeId, sub).Scan(&permissions)
	if err != nil {
		return 0
	}
	if permissions == 0 {
		return 1
	}
	return permissions
}
