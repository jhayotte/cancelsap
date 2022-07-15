package authentication

import (
	"context"
	"crypto/rsa"
	"fmt"
	"strings"

	jwt "github.com/dgrijalva/jwt-go/v4"
	grpc_mdw_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Authenticator defines interface to keycloak for authentication
type Authenticator interface {
	Authenticate(pkey *rsa.PublicKey, saKey string, allowEmpty bool) func(ctx context.Context) (context.Context, error)
	AuthenticateExternal(veepeeSSOPubKey, sourcingSSOPubKey *rsa.PublicKey, allowEmpty bool) func(ctx context.Context) (context.Context, error)
	ParseRSAKey(pubKey *SSOPublicKey) (*rsa.PublicKey, error)
}

type authenticator struct {
	keycloak KeycloakServer
}

// New creates instance of Keycloak Server
func New(keycloak KeycloakServer) Authenticator {
	return &authenticator{
		keycloak: keycloak,
	}
}

// Authenticate function performs authentication logic when receiving call
func (a *authenticator) Authenticate(pkey *rsa.PublicKey, saKey string, allowEmpty bool) func(ctx context.Context) (context.Context, error) {
	return func(ctx context.Context) (context.Context, error) {
		var newCtx context.Context
		currentMethod, _ := grpc.Method(ctx)
		currentMethod = strings.ToLower(currentMethod)

		if allowEmpty || strings.Contains(currentMethod, "health") || strings.Contains(currentMethod, "metrics") {
			newCtx = context.WithValue(ctx, UserInfoCtxKey, true)
			return newCtx, nil
		}

		tokenString, err := grpc_mdw_auth.AuthFromMD(ctx, "bearer")
		if err != nil || tokenString == "" {
			// If no bearer token in incoming request, check sa-token
			saTokenString, basicErr := grpc_mdw_auth.AuthFromMD(ctx, "basic")
			if saTokenString == "" || basicErr != nil {
				return nil, status.Errorf(codes.Unauthenticated, "could not authenticate from metadata: %v - %v", err, basicErr)
			}
			saToken, parseErr := jwt.ParseWithClaims(saTokenString, &SACustomClaims{}, func(token *jwt.Token) (interface{}, error) {
				return []byte(saKey), nil
			})
			if parseErr != nil {
				return nil, status.Errorf(codes.Unauthenticated, "could not authenticate from custom header: %v", parseErr)
			}

			if saClaims, ok := saToken.Claims.(*SACustomClaims); ok && saToken.Valid {
				// Put user claims in the context
				newCtx = context.WithValue(ctx, UserInfoCtxKey, saClaims)
				return newCtx, nil
			}
			return nil, status.Errorf(codes.PermissionDenied, "could not authenticate from custom header: invalid token")
		}

		userClaimsInput, err := verifyTokenWithVeepeeKey(pkey, tokenString)
		if err != nil {
			return nil, status.Errorf(codes.PermissionDenied, "could not verify token with key: %v", err.Error())
		}

		// Converts to get stock_animation_api json tag
		userClaims := UserClaims(*userClaimsInput)
		// Put user claims in the context
		newCtx = context.WithValue(ctx, UserInfoCtxKey, &userClaims)

		// Check header view
		view := metautils.ExtractIncoming(ctx).Get(HeaderView)
		newCtx = context.WithValue(newCtx, ViewCtxKey, view)

		return newCtx, nil
	}
}

// Authenticate function performs authentication logic for external api when receiving call
func (a *authenticator) AuthenticateExternal(veepeeSSOPubKey, sourcingSSOPubKey *rsa.PublicKey, allowEmpty bool) func(ctx context.Context) (context.Context, error) {
	return func(ctx context.Context) (context.Context, error) {
		var newCtx context.Context
		currentMethod, _ := grpc.Method(ctx)
		currentMethod = strings.ToLower(currentMethod)

		if allowEmpty || strings.Contains(currentMethod, "health") || strings.Contains(currentMethod, "metrics") {
			newCtx = context.WithValue(ctx, UserInfoCtxKey, true)
			return newCtx, nil
		}

		tokenString, err := grpc_mdw_auth.AuthFromMD(ctx, "bearer")
		if err != nil || tokenString == "" {
			return nil, status.Errorf(codes.PermissionDenied, "could not authenticate from authorize header: invalid bearer token")
		}

		userClaimsInput, err := verifyTokenWithVeepeeKey(veepeeSSOPubKey, tokenString)
		if err != nil {
			sourcingClaims, err := verifyTokenWithSourcingKey(sourcingSSOPubKey, tokenString)
			if err != nil {
				return nil, status.Errorf(codes.PermissionDenied, "could not verify token with key: %v", err.Error())
			}
			// Put user claims in the context
			newCtx = context.WithValue(ctx, UserInfoCtxKey, sourcingClaims)
		} else {
			// Converts to get stock_animation_api json tag
			userClaims := UserClaims(*userClaimsInput)
			// Put user claims in the context
			newCtx = context.WithValue(ctx, UserInfoCtxKey, &userClaims)
		}

		return newCtx, nil
	}
}

// ParseRSAKey parse struct key as RSA key
func (a *authenticator) ParseRSAKey(pubKey *SSOPublicKey) (*rsa.PublicKey, error) {
	// Add public key separator
	pubKey.PublicKey = fmt.Sprintf("%s\n%s\n%s", "-----BEGIN PUBLIC KEY-----", pubKey.PublicKey, "-----END PUBLIC KEY-----")

	// Parse public key
	rsaKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pubKey.PublicKey))
	if err != nil {
		return nil, errors.Wrap(err, "parse token: could not parse public key")
	}

	return rsaKey, nil
}

// verifyTokenWithVeepeeKey allows to get claims and verify token locally with veepee general sso public key
func verifyTokenWithVeepeeKey(key *rsa.PublicKey, tokenString string) (*UserClaimsInput, error) {
	// Parse token with "account" audience
	token, err := jwt.ParseWithClaims(tokenString, &UserClaimsInput{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("parse token: invalid signing method")
		}
		return key, nil
	}, jwt.WithAudience(AccountAudience))
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "could not parse token: %v", err)
	}
	if token == nil || !token.Valid {
		return nil, status.Errorf(codes.PermissionDenied, "invalid token")
	}

	//  Retrieve user claims from token
	userClaimsInput, ok := token.Claims.(*UserClaimsInput)
	if !ok || userClaimsInput == nil {
		return nil, status.Errorf(codes.Unauthenticated, "malformed claims")
	}

	return userClaimsInput, nil
}

// verifyTokenWithSourcingKey allows to get claims and verify token locally with public key from sourcing keycloak instance (used by brand portal)
func verifyTokenWithSourcingKey(key *rsa.PublicKey, tokenString string) (*SourcingClaims, error) {
	// Parse token with custom user claims
	token, err := jwt.ParseWithClaims(tokenString, &SourcingClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("parse token: invalid signing method")
		}
		return key, nil
	})
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "could not parse token: %v", err)
	}
	if token == nil || !token.Valid {
		return nil, status.Errorf(codes.PermissionDenied, "invalid token")
	}

	//  Retrieve user claims from token
	userClaims, ok := token.Claims.(*SourcingClaims)
	if !ok || userClaims == nil {
		return nil, status.Errorf(codes.Unauthenticated, "malformed claims")
	}

	return userClaims, nil
}
