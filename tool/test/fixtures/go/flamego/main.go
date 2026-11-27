package main

import (
	"context"
	"net/http"

	"github.com/flamego/flamego"
	"github.com/golang-jwt/jwt/v5"
)

type User struct{ ID int64 }

func main() {
	f := flamego.New()
	f.Get("/-/metrics", MetricsFilter, metrics)
	f.Group("/api", func() {
		f.Delete("/passkeys/{id}", deletePasskey)
		f.Delete("/notes/{id}", deleteNote)
		f.Delete("/uploads/{uuid}", deleteUpload)
		f.Delete("/playlists/{id}", svc.deletePlaylist)
	}, requireAuthenticated)
	http.ListenAndServe(":8080", f)
}

func requireAuthenticated(c flamego.Context) {}
func metrics(c flamego.Context)               {}

// basic auth in the body, though the name says metrics
func MetricsFilter(w http.ResponseWriter, r *http.Request) {
	user, pass, _ := r.BasicAuth()
	if user != "prom" || pass != "secret" {
		w.WriteHeader(http.StatusForbidden)
	}
}

// scoped: DeleteByID takes the caller's id; LabelsStore.DeleteByID has the same arity but is not this one
func deletePasskey(c flamego.Context, viewer *User) {
	db.Passkeys().DeleteByID(c.Request().Context(), viewer.ID, c.Param("id"))
}

// vulnerable: no caller anywhere
func deleteNote(c flamego.Context) {
	db.Notes().DeleteByID(c.Param("id"))
}

// vulnerable, but the id is a random UUID
func deleteUpload(c flamego.Context) {
	db.Notes().DeleteByUUID(c.Param("uuid"))
}

// the owner check sits in the implementation behind the Playlists interface
func (s *Service) deletePlaylist(c flamego.Context) {
	s.playlists.Delete(c.Request().Context(), c.Param("id"))
}

func kidOf(token string) string {
	t, _, _ := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	kid, _ := t.Header["kid"].(string)
	return kid
}

func claimsOf(token string) jwt.MapClaims {
	claims := jwt.MapClaims{}
	jwt.NewParser().ParseUnverified(token, claims)
	return claims
}

var _ = context.Background
