package security

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

func GetPrivilegesFromContext(r *http.Request) []string {
	token := r.Context().Value(Authorization)
	privileges := make([]string, 0)
	if authorizationToken, ok1 := token.(map[string]interface{}); ok1 {
		pPrivileges, ok2 := authorizationToken["privileges"]
		if !ok2 || pPrivileges == nil {
			return privileges
		}
		if rawPrivileges, ok3 := pPrivileges.([]interface{}); ok3 {
			for _, rawPrivilege := range rawPrivileges {
				if s, ok4 := rawPrivilege.(string); ok4 {
					privileges = append(privileges, s)
				}
			}
		}
	}
	return privileges
}

func GetPositionFromSortedPrivileges(privileges []string, privilegeId string) int {
	return sort.Search(len(privileges), func(i int) bool { return privileges[i][:strings.Index(privileges[i], ":")] >= privilegeId })
}

func GetAction(privileges []string, privilegeId string, sortedPrivilege bool) int32 {
	prefix := fmt.Sprintf("%s:", privilegeId)
	prefixLen := len(prefix)

	if sortedPrivilege {
		i := GetPositionFromSortedPrivileges(privileges, privilegeId)
		if i >= 0 && i < len(privileges) && strings.HasPrefix(privileges[i], prefix) {
			hexAction := privileges[i][prefixLen:]
			if action, err := ConvertHexAction(hexAction); err == nil {
				return action
			}
		}
	} else {
		for _, privilege := range privileges {
			if strings.HasPrefix(privilege, prefix) {
				hexAction := privilege[prefixLen:]
				if action, err := ConvertHexAction(hexAction); err == nil {
					return action
				}
			}
		}
	}

	return ActionNone
}

func ConvertHexAction(hexAction string) (int32, error) {
	if action64, err := strconv.ParseInt(hexAction, 16, 64); err == nil {
		return int32(action64), nil
	} else {
		return 0, err
	}
}
