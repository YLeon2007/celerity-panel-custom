package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// User represents a VLESS user managed by the agent
type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Flow  string `json:"flow"`
}

type persistedData struct {
	Users    []*User   `json:"users"`
	LastSync time.Time `json:"lastSync"`
}

// UserStore holds users in memory and persists them to disk
type UserStore struct {
	mu       sync.RWMutex
	users    map[string]*User // keyed by email
	filePath string
	lastSync time.Time
}

func NewUserStore(cfg *Config) *UserStore {
	return &UserStore{
		users:    make(map[string]*User),
		filePath: filepath.Join(cfg.DataDir, "users.json"),
	}
}

func (s *UserStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var pd persistedData
	if err := json.Unmarshal(data, &pd); err != nil {
		return err
	}

	for _, u := range pd.Users {
		s.users[u.Email] = u
	}
	s.lastSync = pd.LastSync
	log.Printf("[store] Loaded %d users from %s", len(s.users), s.filePath)
	return nil
}

func (s *UserStore) Save() error {
	s.mu.RLock()
	users := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, u)
	}
	lastSync := s.lastSync
	s.mu.RUnlock()

	pd := persistedData{
		Users:    users,
		LastSync: lastSync,
	}

	data, err := json.MarshalIndent(pd, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(s.filePath), 0755); err != nil {
		return err
	}

	return os.WriteFile(s.filePath, data, 0600)
}

func (s *UserStore) Add(u *User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.Email] = u
}

func (s *UserStore) Remove(email string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, email)
}

func (s *UserStore) List() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	users := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, u)
	}
	return users
}

func (s *UserStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

// Sync replaces all users and updates lastSync
func (s *UserStore) Sync(users []*User) {
	s.mu.Lock()
	s.users = make(map[string]*User, len(users))
	for _, u := range users {
		s.users[u.Email] = u
	}
	s.lastSync = time.Now()
	s.mu.Unlock()
}

func (s *UserStore) SetLastSync(t time.Time) {
	s.mu.Lock()
	s.lastSync = t
	s.mu.Unlock()
}

func (s *UserStore) GetLastSync() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSync
}
