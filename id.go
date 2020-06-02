package security

func GetUserId(data map[string]interface{}) string {
	u := data["userId"]
	if u != nil {
		userId, _ := u.(string)
		return userId
	} else {
		u = data["userid"]
		if u != nil {
			userId, _ := u.(string)
			return userId
		} else {
			u = data["uid"]
			userId, _ := u.(string)
			return userId
		}
	}
	return GetUserName(data)
}

func GetUserName(data map[string]interface{}) string {
	u := data["username"]
	if u != nil {
		userName, _ := u.(string)
		return userName
	} else {
		u = data["userName"]
		userName, _ := u.(string)
		return userName
	}
	return ""
}

func GetUserType(data map[string]interface{}) string {
	u := data["userType"]
	if u != nil {
		userId, _ := u.(string)
		return userId
	} else {
		u = data["usertype"]
		if u != nil {
			userId, _ := u.(string)
			return userId
		} else {
			u = data["utype"]
			userId, _ := u.(string)
			return userId
		}
	}
	return ""
}
