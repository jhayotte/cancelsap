package main

import jwt "github.com/dgrijalva/jwt-go/v4"

const (
	// HeaderView represents the header view that carries the view warehouse requested
	HeaderView string = "view"

	// AccountAudience represents the account audience for SSO
	AccountAudience = "account"
)

var (
	// AuthorizationCtxKey define the key within HttpHeader
	AuthorizationCtxKey = &ContextKey{"authorization"}
	// UserInfoCtxKey is key for User Claims in context
	UserInfoCtxKey = &ContextKey{"userinfo"}
	// ViewCtxKey define the key for current view
	ViewCtxKey = &ContextKey{HeaderView}
	// AllowedWarehousesCtxKey is the key of allow policy of user in the context.
	AllowedWarehousesCtxKey = &ContextKey{"allowed_warehouses"}
	// PreferredUsernameCtxKey is the key of the name identifying a user.
	PreferredUsernameCtxKey = &ContextKey{"preferred_username"}
	// RestrictedCtxKey is the key of has_restricted_access in the context.
	RestrictedCtxKey = &ContextKey{"has_restricted_access"}
	// IsAdminCtxKey is the key of is_admin in the context.
	IsAdminCtxKey = &ContextKey{"is_admin"}
	// RolesCtxKey is the key of user roles.
	RolesCtxKey = &ContextKey{"roles"}
)

// ContextKey in context
type ContextKey struct {
	Key string
}

// ContextKeyValue represents a pair of ContextKey and its Value in context
type ContextKeyValue struct {
	Key   *ContextKey
	Value interface{}
}

// SSOClaim represents the SSO struct containing the access claim
type SSOClaim struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	SessionState string `json:"session_state"`
}

// SSOCredentials holds sam sso information keycloak server url
type SSOCredentials struct {
	AuthURL  string
	Realm    string
	ClientID string
	Secret   string
}

// SACustomClaims represents the custom claim contain in token from sa services
type SACustomClaims struct {
	From string `json:"frm"`
	jwt.StandardClaims
}

// SSOPublicKey holds public key
type SSOPublicKey struct {
	PublicKey string `json:"public_key"`
}

// SourcingClaims are claims contained in Token from Sourcing keyclaok (Brand Portal authentication)
type SourcingClaims struct {
	FirstName   string `json:"firstName,omitempty"`
	LastName    string `json:"lastName,omitempty"`
	Email       string `json:"email,omitempty"`
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access,omitempty"`
	ReferentialIDs []string `json:"referentialIds,omitempty"`
	jwt.StandardClaims
}

// UserClaims struct containing user info to put in context
/* Used to change json tag from sam_api to sam_api
   for later use in rego`*/
type UserClaims struct {
	Email             string `json:"email,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Sub               string `json:"sub,omitempty"`
	IsActive          bool   `json:"active,omitempty"` // If Token is active
	ResourceAccess    struct {
		SamAPI struct {
			Roles []string `json:"roles"`
		} `json:"sam_api"`
	} `json:"resource_access,omitempty"`
	Groups []string `json:"groups,omitempty"`
	jwt.StandardClaims
}

// UserClaimsInput struct containing user info from token sent by keycloak
// See partial example
/*
{
  "sub": "3e8b29a1128dajndoas",
  "name": "Alison CELLARD",
  "given_name": "Alison",
  "family_name": "CELLARD",
  "preferred_username": "acellard",
  "email": "acellard@veepee.com",
  "resource_access": {
    "sam_api": {
      "roles": [
        "Return Coordinator",
        "Santa-Oliva A"
      ]
    }
  },
  "groups": [
    "/sam/blanc-mesnil-id-2"
  ],
  "username": "acellard",
  "active": true
}
*/
type UserClaimsInput struct {
	Email             string `json:"email,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Sub               string `json:"sub,omitempty"`
	IsActive          bool   `json:"active,omitempty"` // If Token is active
	ResourceAccess    struct {
		SamAPI struct {
			Roles []string `json:"roles"`
		} `json:"sam_api"` // client name given by keycloak for sam api
	} `json:"resource_access,omitempty"`
	Groups []string `json:"groups,omitempty"`
	jwt.StandardClaims
}

// UserInfo holds some infos on authenticated user
type UserInfo struct {
	PreferredUsername         string
	IsAdmin                   bool
	WarehouseRestrictedAccess bool
	WarehouseView             string
	AllowedWarehouses         []string
	Roles                     []string
}
