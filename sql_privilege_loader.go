package security

import (
	"context"
	"database/sql"
)

type SqlPrivilegeLoader struct {
	DB    *sql.DB
	Query string
}

func NewSqlPrivilegeLoader(db *sql.DB, query string) *SqlPrivilegeLoader{
	return &SqlPrivilegeLoader{DB: db, Query: query}
}
func (l SqlPrivilegeLoader) Privilege(ctx context.Context, userId string, privilegeId string) int32 {
	var permissions int32 = 0
	err := l.DB.QueryRow(l.Query, userId, privilegeId).Scan(&permissions)
	if err != nil {
		return ActionNone
	}
	if permissions == ActionNone {
		return ActionAll
	}
	return permissions
}
