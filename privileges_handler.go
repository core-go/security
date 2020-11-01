package security

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
)

type PrivilegesHandler struct {
	PrivilegeLoader  PrivilegeLoader
	PrivilegesLoader PrivilegesLoader
}

func PrivilegeHandler(privilegeLoader PrivilegeLoader, privilegesLoader PrivilegesLoader) *PrivilegesHandler {
	return &PrivilegesHandler{PrivilegeLoader: privilegeLoader, PrivilegesLoader: privilegesLoader}
}

func (h *PrivilegesHandler) Privileges(w http.ResponseWriter, r *http.Request) {
	id := ""
	if r.Method == "GET" {
		i := strings.LastIndex(r.RequestURI, "/")
		if i >= 0 {
			id = r.RequestURI[i+1:]
		}
	} else {
		b, er1 := ioutil.ReadAll(r.Body)
		if er1 != nil {
			respondString(w, r, http.StatusBadRequest, "Require UserId")
			return
		}
		id = strings.Trim(string(b), " ")
	}
	if len(id) == 0 {
		respondString(w, r, http.StatusBadRequest, "Require UserId")
		return
	}
	result := h.PrivilegesLoader.Privileges(r.Context(), id)
	respond(w, r, http.StatusOK, result)
}
func (h *PrivilegesHandler) Privilege(w http.ResponseWriter, r *http.Request) {
	s := strings.Split(r.RequestURI, "/")
	if len(s) < 3 {
		respondString(w, r, http.StatusBadRequest, "URL is not valid")
		return
	}

	if r.Method != "GET" {
		respondString(w, r, http.StatusBadRequest, "Must use GET method")
		return
	}
	userId := s[len(s)-2]
	privilegeId := s[len(s)-1]
	if len(userId) == 0 || len(privilegeId) == 0 {
		respondString(w, r, http.StatusBadRequest, "parameters cannot be empty")
		return
	}
	result := h.PrivilegeLoader.Privilege(r.Context(), userId, privilegeId)
	respond(w, r, http.StatusOK, result)
}
func respondString(w http.ResponseWriter, r *http.Request, code int, result string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write([]byte(result))
}
func respond(w http.ResponseWriter, r *http.Request, code int, result interface{}) {
	response, _ := json.Marshal(result)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}
