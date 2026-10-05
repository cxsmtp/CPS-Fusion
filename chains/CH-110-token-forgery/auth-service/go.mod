// Nexa Commerce auth service.
//
// One dependency: golang-jwt, pinned to a current release so the SCA surface
// carries no High or Critical advisory. It is required because
// JWT_No_Claims_Directives_Validation only fires against a real JWT parser.
//
// Run `go mod tidy` after checkout to generate go.sum.
module github.com/nexa-commerce/auth-service

go 1.22

require github.com/golang-jwt/jwt/v5 v5.2.1
