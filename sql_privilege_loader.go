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
		driver := GetDriver(db)
		query = ReplaceQueryArgs(driver, query)
	}
	return &SqlPrivilegeLoader{DB: db, Query: query}
}

func (l SqlPrivilegeLoader) Privilege(ctx context.Context, userId string, privilegeId string) int32 {
	var permissions int32 = 0
	rows, er0 := l.DB.Query(l.Query, userId, privilegeId)
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

func ReplaceQueryArgs(driver string, query string) string {
	if driver == DriverOracle || driver == DriverPostgres {
		var x string
		if driver == DriverOracle {
			x = ":val"
		} else {
			x = "$"
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

func GetDriver(db *sql.DB) string {
	if db == nil {
		return DriverNotSupport
	}
	driver := reflect.TypeOf(db.Driver()).String()
	switch driver {
	case "*pq.Driver":
		return DriverPostgres
	case "*mysql.MySQLDriver":
		return DriverMysql
	case "*mssql.Driver":
		return DriverMssql
	case "*godror.drv":
		return DriverOracle
	default:
		return DriverNotSupport
	}
}
