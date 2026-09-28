package main

import (
	"encoding/json"
	"errors"
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
	mu        sync.RWMutex
	users     map[string]*User // keyed by email
	filePath  string
	lastSync  time.Time
	stopped   bool
	stopDone  chan struct{}
	stopErr   error
	pending   sync.WaitGroup             // admitted Save calls, including unscheduled async calls
	mutations sync.WaitGroup             // HTTP mutations admitted before Stop's fence
	writeMu   sync.Mutex                 // serialize snapshots and disk writes together
	writeFile func(string, []byte) error // test seam at the actual disk write
}

var errUserStoreStopped = errors.New("user store stopped")

func (s *UserStore) acceptingMutations() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.stopped
}

// admitMutation leases the entire HTTP -> Xray -> store -> persister operation.
// Stop closes admission under mu before waiting, so WaitGroup.Add cannot race
// with Wait. The lease's local store updates remain valid after the fence.
func (s *UserStore) admitMutation() *mutationLease {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return nil
	}
	s.mutations.Add(1)
	return &mutationLease{store: s}
}

type mutationLease struct{ store *UserStore }

func (m *mutationLease) Done() { m.store.mutations.Done() }

func (m *mutationLease) Add(u *User) {
	m.store.mu.Lock()
	defer m.store.mu.Unlock()
	m.store.users[u.Email] = u
}

func (m *mutationLease) Remove(email string) {
	m.store.mu.Lock()
	defer m.store.mu.Unlock()
	delete(m.store.users, email)
}

func (m *mutationLease) Sync(users []*User) {
	m.store.mu.Lock()
	defer m.store.mu.Unlock()
	m.store.users = make(map[string]*User, len(users))
	for _, u := range users {
		m.store.users[u.Email] = u
	}
	m.store.lastSync = time.Now()
}

func NewUserStore(cfg *Config) *UserStore {
	return &UserStore{
		users:     make(map[string]*User),
		filePath:  filepath.Join(cfg.DataDir, "users.json"),
		stopDone:  make(chan struct{}),
		writeFile: func(path string, data []byte) error { return os.WriteFile(path, data, 0600) },
	}
}

func (s *UserStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return errUserStoreStopped
	}

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
	if !s.admitSave() {
		return errUserStoreStopped
	}
	defer s.pending.Done()
	return s.saveSnapshot()
}

// SaveAsync registers the write before returning to its caller, so Stop can
// drain it even if the goroutine has not been scheduled yet.
func (s *UserStore) SaveAsync() bool {
	if !s.admitSave() {
		return false
	}
	go func() {
		defer s.pending.Done()
		if err := s.saveSnapshot(); err != nil {
			log.Printf("[store] Save: %v", err)
		}
	}()
	return true
}

func (s *UserStore) admitSave() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return false
	}
	s.pending.Add(1)
	return true
}

// Stop closes write and mutation admission, joins admitted HTTP mutations and
// writes, then persists the final state exactly once. It does not fence external writers.
func (s *UserStore) Stop() error {
	s.mu.Lock()
	if s.stopped {
		done := s.stopDone
		s.mu.Unlock()
		<-done
		return s.stopErr
	}
	s.stopped = true
	s.mu.Unlock()
	s.mutations.Wait()
	s.pending.Wait()
	s.stopErr = s.saveSnapshot()
	close(s.stopDone)
	return s.stopErr
}

func (s *UserStore) saveSnapshot() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
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

	return s.writeFile(s.filePath, data)
}

func (s *UserStore) Add(u *User) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return false
	}
	s.users[u.Email] = u
	return true
}

func (s *UserStore) Remove(email string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return false
	}
	delete(s.users, email)
	return true
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
func (s *UserStore) Sync(users []*User) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return false
	}
	s.users = make(map[string]*User, len(users))
	for _, u := range users {
		s.users[u.Email] = u
	}
	s.lastSync = time.Now()
	return true
}

func (s *UserStore) SetLastSync(t time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return false
	}
	s.lastSync = t
	return true
}

func (s *UserStore) GetLastSync() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSync
}
