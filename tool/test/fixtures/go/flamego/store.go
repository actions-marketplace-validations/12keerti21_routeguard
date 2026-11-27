package main

import (
	"context"
	"errors"

	"gorm.io/gorm"
)

type DB struct{ db *gorm.DB }

var db *DB

func (d *DB) Passkeys() *PasskeysStore { return &PasskeysStore{d.db} }
func (d *DB) Notes() *NotesStore       { return &NotesStore{d.db} }

type PasskeysStore struct{ db *gorm.DB }
type LabelsStore struct{ db *gorm.DB }
type NotesStore struct{ db *gorm.DB }

func (s *PasskeysStore) DeleteByID(ctx context.Context, userID int64, id string) error {
	return s.db.Where("id = ? AND user_id = ?", id, userID).Delete(&Passkey{}).Error
}

func (s *LabelsStore) DeleteByID(ctx context.Context, repoID int64, id string) error {
	return s.db.Where("id = ?", id).Delete(&Label{}).Error
}

func (s *NotesStore) DeleteByID(id string) error {
	return s.db.Where("id = ?", id).Delete(&Note{}).Error
}

func (s *NotesStore) DeleteByUUID(uuid string) error {
	return s.db.Where("uuid = ?", uuid).Delete(&Note{}).Error
}

type Passkey struct{ ID string }
type Label struct{ ID string }
type Note struct{ ID string }

type Playlists interface {
	Delete(ctx context.Context, id string) error
}

type Service struct{ playlists Playlists }

var svc = &Service{}

type playlists struct{ db *gorm.DB }

type Playlist struct{ OwnerID int64 }

func (p *playlists) Delete(ctx context.Context, id string) error {
	var pls Playlist
	p.db.First(&pls, id)
	user := UserFrom(ctx)
	if pls.OwnerID != user.ID {
		return errors.New("not authorised")
	}
	return p.db.Delete(&pls).Error
}

func UserFrom(ctx context.Context) *User { return ctx.Value("user").(*User) }
