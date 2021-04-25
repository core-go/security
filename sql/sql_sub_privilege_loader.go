package sql

import (
	"context"
	"database/sql"
)

type SqlSubPrivilegeLoader struct {
	DB    *sql.DB
	Query string
}

func NewSubPrivilegeLoader(db *sql.DB, query string, options ...bool) *SqlSubPrivilegeLoader {
	var handleDriver bool
	if len(options) >= 1 {
		handleDriver = options[0]
	} else {
		handleDriver = true
	}
	if handleDriver {
		driver := getDriver(db)
		query = replaceQueryArgs(driver, query)
	}
	return &SqlSubPrivilegeLoader{DB: db, Query: query}
}
func (l SqlSubPrivilegeLoader) Privilege(ctx context.Context, userId string, privilegeId string, sub string) int32 {
	var permissions int32 = 0
	rows, er0 := l.DB.QueryContext(ctx, l.Query, userId, privilegeId, sub)
	if er0 != nil {
		return actionNone
	}
	defer rows.Close()
	for rows.Next() {
		var action int32
		er1 := rows.Scan(&action)
		if er1 != nil {
			return actionNone
		}
		permissions = permissions | action
	}
	if permissions == actionNone {
		return actionAll
	}
	return permissions
}
