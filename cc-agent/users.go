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
	mu           sync.RWMutex
	users        map[string]*User // keyed by email
	filePath     string
	lastSync     time.Time
	awaitingSync bool // guarded by mu; only an authoritative /sync can release recovery
	stopped      bool
	stopDone     chan struct{}
	stopErr      error
	pending      sync.WaitGroup             // admitted Save calls, including unscheduled async calls
	mutations    sync.WaitGroup             // HTTP mutations admitted before Stop's fence
	writeMu      sync.Mutex                 // serialize snapshots and disk writes together
	writeFile    func(string, []byte) error // test seam at the actual disk write

	// Order the empty-startup checks and writes across both files with /sync's
	// commit. Acquire startupMu before mu; snapshot writers release mu before I/O.
	startupMu    sync.Mutex
	startupCheck func() error // guarded by startupMu; active only after a successful empty Load
}

var errUserStoreStopped = errors.New("user store stopped")

func (s *UserStore) needsFullSync() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.awaitingSync
}

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
	m.store.startupMu.Lock()
	defer m.store.startupMu.Unlock()
	m.store.mu.Lock()
	defer m.store.mu.Unlock()
	m.store.users = make(map[string]*User, len(users))
	for _, u := range users {
		m.store.users[u.Email] = u
	}
	m.store.lastSync = time.Now()
	m.store.awaitingSync = false
	m.store.startupCheck = nil
}

func NewUserStore(cfg *Config) *UserStore {
	return &UserStore{
		users:     make(map[string]*User),
		filePath:  filepath.Join(cfg.DataDir, "users.json"),
		stopDone:  make(chan struct{}),
		writeFile: func(path string, data []byte) error { return atomicWriteMode(path, data, 0600) },
	}
}

func (s *UserStore) Load(checkEmpty func() error) error {
	s.startupMu.Lock()
	defer s.startupMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return errUserStoreStopped
	}

	// No local snapshot is authoritative until the entire load and the empty-store check succeed.
	s.awaitingSync = true
	s.startupCheck = nil
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}

	var pd persistedData
	if err := json.Unmarshal(data, &pd); err != nil {
		return err
	}

	byEmail, err := indexSnapshot(pd.Users)
	if err != nil {
		return err
	}
	if len(byEmail) == 0 {
		if err := checkEmpty(); err != nil {
			return err
		}
		// Persisted LastSync is historical, not authority for this process.
		s.startupCheck = checkEmpty
	}
	s.users = byEmail
	s.awaitingSync = false
	s.lastSync = pd.LastSync
	log.Printf("[store] Loaded %d users from %s", len(s.users), s.filePath)
	return nil
}

// Distinguish an explicit empty list from a missing, null or partial snapshot.
func indexSnapshot(users []*User) (map[string]*User, error) {
	if users == nil {
		return nil, errors.New("users array required")
	}
	out := make(map[string]*User, len(users))
	for _, u := range users {
		if u == nil || u.ID == "" || u.Email == "" || out[u.Email] != nil {
			return nil, errors.New("incomplete or duplicate user in snapshot")
		}
		out[u.Email] = u
	}
	return out, nil
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

// persistenceSnapshot returns one coherent view of the users and recovery state.
// While the empty-startup check is active, done releases the gate after the
// caller finishes checking and publishing, not merely after taking the snapshot.
func (s *UserStore) persistenceSnapshot() (pd persistedData, ok bool, check func() error, done func()) {
	s.startupMu.Lock()
	s.mu.RLock()
	if !s.awaitingSync {
		pd = persistedData{Users: s.listLocked(), LastSync: s.lastSync}
		ok = true
	}
	s.mu.RUnlock()
	if ok && s.startupCheck != nil {
		return pd, true, s.startupCheck, s.startupMu.Unlock
	}
	s.startupMu.Unlock()
	return pd, ok, nil, func() {}
}

// Called with startupMu held. A conflicting config is not a basis for either
// file's next snapshot; the full /sync commit is the only exit from recovery.
func (s *UserStore) checkStartupConflict(err error) error {
	if errors.Is(err, errStartupConfigClients) {
		s.mu.Lock()
		s.awaitingSync = true
		s.mu.Unlock()
		s.startupCheck = nil
		log.Printf("[store] Preserving users and Xray config until full /sync: %v", err)
		return nil
	}
	return err
}

func (s *UserStore) saveSnapshot() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	pd, ok, check, done := s.persistenceSnapshot()
	defer done()
	if !ok {
		return nil
	}
	if check != nil {
		if err := check(); err != nil {
			return s.checkStartupConflict(err)
		}
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
	return s.listLocked()
}

func (s *UserStore) listLocked() []*User {
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
