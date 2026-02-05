package bookmarks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/natevick/s3-tui/internal/security"
)

// Bookmark represents a saved S3 location
type Bookmark struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Bucket    string    `json:"bucket"`
	Prefix    string    `json:"prefix"`
	CreatedAt time.Time `json:"created_at"`
}

// DisplayName returns the bookmark display name
func (b Bookmark) DisplayName() string {
	if b.Name != "" {
		return b.Name
	}
	if b.Prefix != "" {
		return fmt.Sprintf("s3://%s/%s", b.Bucket, b.Prefix)
	}
	return fmt.Sprintf("s3://%s", b.Bucket)
}

// Path returns the full S3 path
func (b Bookmark) Path() string {
	if b.Prefix != "" {
		return fmt.Sprintf("s3://%s/%s", b.Bucket, b.Prefix)
	}
	return fmt.Sprintf("s3://%s", b.Bucket)
}

// Store manages bookmark persistence
type Store struct {
	path      string
	bookmarks []Bookmark
}

// NewStore creates a new bookmark store
func NewStore() (*Store, error) {
	configDir, err := getConfigDir()
	if err != nil {
		return nil, err
	}

	path := filepath.Join(configDir, "bookmarks.json")

	store := &Store{
		path:      path,
		bookmarks: []Bookmark{},
	}

	// Try to load existing bookmarks
	if err := store.Load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	return store, nil
}

// getConfigDir returns the config directory path
func getConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	configDir := filepath.Join(homeDir, ".config", "s3-tui")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create config directory: %w", err)
	}

	return configDir, nil
}

// Load reads bookmarks from disk
func (s *Store) Load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &s.bookmarks)
}

// Save writes bookmarks to disk
func (s *Store) Save() error {
	data, err := json.MarshalIndent(s.bookmarks, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal bookmarks: %w", err)
	}

	if err := os.WriteFile(s.path, data, 0600); err != nil {
		return fmt.Errorf("failed to write bookmarks: %w", err)
	}

	return nil
}

// Add creates a new bookmark
func (s *Store) Add(name, bucket, prefix string) (Bookmark, error) {
	// Validate inputs
	if err := security.ValidBookmarkName(name); err != nil {
		return Bookmark{}, err
	}
	if err := security.ValidBucketName(bucket); err != nil {
		return Bookmark{}, err
	}

	bookmark := Bookmark{
		ID:        uuid.New().String(),
		Name:      name,
		Bucket:    bucket,
		Prefix:    prefix,
		CreatedAt: time.Now(),
	}

	s.bookmarks = append(s.bookmarks, bookmark)

	if err := s.Save(); err != nil {
		// Remove the bookmark if save failed
		s.bookmarks = s.bookmarks[:len(s.bookmarks)-1]
		return Bookmark{}, err
	}

	return bookmark, nil
}

// Remove deletes a bookmark by ID
func (s *Store) Remove(id string) error {
	for i, b := range s.bookmarks {
		if b.ID == id {
			s.bookmarks = append(s.bookmarks[:i], s.bookmarks[i+1:]...)
			return s.Save()
		}
	}
	return fmt.Errorf("bookmark not found: %s", id)
}

// List returns all bookmarks
func (s *Store) List() []Bookmark {
	return s.bookmarks
}

// Get returns a bookmark by ID
func (s *Store) Get(id string) (Bookmark, bool) {
	for _, b := range s.bookmarks {
		if b.ID == id {
			return b, true
		}
	}
	return Bookmark{}, false
}

// Update modifies an existing bookmark
func (s *Store) Update(id, name string) error {
	for i, b := range s.bookmarks {
		if b.ID == id {
			s.bookmarks[i].Name = name
			return s.Save()
		}
	}
	return fmt.Errorf("bookmark not found: %s", id)
}

// FindByPath finds a bookmark by bucket and prefix
func (s *Store) FindByPath(bucket, prefix string) (Bookmark, bool) {
	for _, b := range s.bookmarks {
		if b.Bucket == bucket && b.Prefix == prefix {
			return b, true
		}
	}
	return Bookmark{}, false
}
