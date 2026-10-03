package web

import (
	"net/http/httptest"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/internal/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/internal/errors"
	"github.com/gtsteffaniak/filebrowser/backend/internal/state"
	"github.com/gtsteffaniak/filebrowser/backend/pkg/settings"
)

func TestOIDCLinkedSubjectUsesAdminChosenUsername(t *testing.T) {
	setupTestEnv(t)
	issuer := "https://issuer.example"
	user := &users.User{FrontendUser: users.FrontendUser{Username: "admin-chosen", LoginMethod: users.LoginMethodOidc}}
	if err := state.CreateUser(user, ""); err != nil {
		t.Fatal(err)
	}
	if err := state.SetOIDCIdentity(user.ID, issuer, "stable-subject"); err != nil {
		t.Fatal(err)
	}
	oldIssuer := settings.Config.Auth.Methods.OidcAuth.IssuerUrl
	oldAutoCreate := settings.Config.Auth.Methods.OidcAuth.AutoCreateUsers
	oldTokenExpiration := settings.Config.Auth.TokenExpirationHours
	settings.Config.Auth.Methods.OidcAuth.IssuerUrl = issuer
	disabled := false
	settings.Config.Auth.Methods.OidcAuth.AutoCreateUsers = &disabled
	settings.Config.Auth.TokenExpirationHours = 2
	t.Cleanup(func() {
		settings.Config.Auth.Methods.OidcAuth.IssuerUrl = oldIssuer
		settings.Config.Auth.Methods.OidcAuth.AutoCreateUsers = oldAutoCreate
		settings.Config.Auth.TokenExpirationHours = oldTokenExpiration
	})
	req := httptest.NewRequest("GET", "/api/auth/oidc/callback", nil)
	rec := httptest.NewRecorder()
	status, err := loginWithOidcIdentity(rec, req, issuer, "stable-subject", "provider-renamed", nil, "/")
	if err != nil || status != 0 {
		t.Fatalf("loginWithOidcIdentity status=%d err=%v", status, err)
	}
	loaded, err := state.GetUserByID(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Username != "admin-chosen" {
		t.Fatalf("username changed to provider claim %q", loaded.Username)
	}
}

func TestOIDCUnknownSubjectDoesNotCreateUserWhenDisabled(t *testing.T) {
	setupTestEnv(t)
	oldIssuer := settings.Config.Auth.Methods.OidcAuth.IssuerUrl
	oldAutoCreate := settings.Config.Auth.Methods.OidcAuth.AutoCreateUsers
	settings.Config.Auth.Methods.OidcAuth.IssuerUrl = "https://issuer.example"
	disabled := false
	settings.Config.Auth.Methods.OidcAuth.AutoCreateUsers = &disabled
	t.Cleanup(func() {
		settings.Config.Auth.Methods.OidcAuth.IssuerUrl = oldIssuer
		settings.Config.Auth.Methods.OidcAuth.AutoCreateUsers = oldAutoCreate
	})
	req := httptest.NewRequest("GET", "/api/auth/oidc/callback", nil)
	rec := httptest.NewRecorder()
	status, err := loginWithOidcIdentity(rec, req, "https://issuer.example", "unmapped-subject", "would-create-user", nil, "/")
	if status != 401 || err == nil {
		t.Fatalf("expected unmapped subject rejection, status=%d err=%v", status, err)
	}
	if _, err := state.GetUserByUsername("would-create-user"); err != errors.ErrNotExist {
		t.Fatalf("unknown OIDC subject created a user: %v", err)
	}
}
