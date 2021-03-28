package security

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"strings"
)

const (
	DriverPostgres   = "postgres"
	DriverMysql      = "mysql"
	DriverMssql      = "mssql"
	DriverOracle     = "oracle"
	DriverSqlite3    = "sqlite3"
	DriverNotSupport = "no support"
)

type SqlPrivilegeLoader struct {
	DB    *sql.DB
	Query string
}

func NewPrivilegeLoader(db *sql.DB, query string, options ...bool) *SqlPrivilegeLoader {
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
	return &SqlPrivilegeLoader{DB: db, Query: query}
}

func (l SqlPrivilegeLoader) Privilege(ctx context.Context, userId string, privilegeId string) int32 {
	var permissions int32 = 0
	rows, er0 := l.DB.QueryContext(ctx, l.Query, userId, privilegeId)
	if er0 != nil {
		return ActionNone
	}
	defer rows.Close()
	for rows.Next() {
		var action int32
		er1 := rows.Scan(&action)
		if er1 != nil {
			return ActionNone
		}
		permissions = permissions | action
	}
	if permissions == ActionNone {
		return ActionAll
	}
	return permissions
}

func replaceQueryArgs(driver string, query string) string {
	if driver == DriverOracle || driver == DriverPostgres || driver == DriverMssql {
		var x string
		if driver == DriverOracle {
			x = ":val"
		} else if driver == DriverPostgres {
			x = "$"
		} else if driver == DriverMssql {
			x = "@p"
		}
		i := 1
		k := strings.Index(query, "?")
		if k >= 0 {
			for {
				query = strings.Replace(query, "?", x+fmt.Sprintf("%v", i), 1)
				i = i + 1
				k := strings.Index(query, "?")
				if k < 0 {
					return query
				}
			}
		}
	}
	return query
}

func getDriver(db *sql.DB) string {
	if db == nil {
		return DriverNotSupport
	}
	driver := reflect.TypeOf(db.Driver()).String()
	switch driver {
	case "*pq.Driver":
		return DriverPostgres
	case "*godror.drv":
		return DriverOracle
	case "*mysql.MySQLDriver":
		return DriverMysql
	case "*mssql.Driver":
		return DriverMssql
	case "*sqlite3.SQLiteDriver":
		return DriverSqlite3
	default:
		return DriverNotSupport
	}
}
