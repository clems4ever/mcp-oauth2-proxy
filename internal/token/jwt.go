package token

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims is the JWT payload for an access token.
type Claims struct {
	Scope string `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

// Generate signs and returns a JWT access token for the given client using HMAC-SHA256.
//
// @arg secret HMAC signing key used to sign the token.
// @arg issuer Value set as both the "iss" and "aud" claims.
// @arg clientID Value set as the "sub" (subject) claim.
// @arg scopes OAuth 2.0 scopes granted to the token; joined as a space-separated string in the "scope" claim.
// @arg ttlSeconds Token lifetime in seconds from the current time.
// @return string The signed compact JWT string.
// @error Returns an error if the token cannot be signed.
//
// @testcase TestGenerate_ReturnsToken verifies that a non-empty three-part JWT is returned for valid inputs.
// @testcase TestGenerate_Claims verifies that the subject and scope claims are correctly embedded.
// @testcase TestGenerate_EmptyScopes verifies that an empty scope list results in an empty scope claim.
// @testcase TestGenerate_Expiry verifies that the expiry claim is set to approximately now plus ttlSeconds.
func Generate(secret, issuer, clientID string, scopes []string, ttlSeconds int) (string, error) {
	now := time.Now()
	claims := Claims{
		Scope: strings.Join(scopes, " "),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{issuer},
			Subject:   clientID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(ttlSeconds) * time.Second)),
		},
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("signing token: %w", err)
	}
	return signed, nil
}

// Verify parses and validates a signed JWT, returning the claims on success.
//
// @arg secret HMAC key used to verify the token signature.
// @arg issuer Expected value of the "iss" and "aud" claims.
// @arg tokenString The compact serialised JWT string to verify.
// @return *Claims The parsed claims extracted from the token.
// @error Returns an error if the token is malformed, expired, uses an unexpected signing method, or fails signature verification.
//
// @testcase TestVerify_ValidToken verifies that a freshly generated token is accepted and claims are returned.
// @testcase TestVerify_WrongSecret verifies that a token signed with a different secret is rejected.
// @testcase TestVerify_ExpiredToken verifies that an expired token is rejected.
// @testcase TestVerify_MalformedToken verifies that a malformed token string is rejected.
// @testcase TestVerify_WrongAlgorithm verifies that a token using an unexpected signing algorithm is rejected.
func Verify(secret, issuer, tokenString string) (*Claims, error) {
	tok, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	},
		jwt.WithIssuer(issuer),
		jwt.WithAudience(issuer),
	)
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(*Claims)
	if !ok || !tok.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}
