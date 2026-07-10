// NOTE: this file uses syscall.Stat_t and only builds for GOOS=linux targets.
// The agent is always cross-compiled for linux (amd64/arm64); building for a
// non-linux host OS is not supported.

package main

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// cursorState is persisted so the tailer resumes at the right position after an
// agent restart and detects file recreation (rotation / truncation by another
// tool) via device+inode identity.
type cursorState struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

// rawLine is a single completed access-log line with the byte offset at which
// it started. The offset feeds the deterministic event id on the panel so
// retries dedup while genuine repeats stay distinct.
type rawLine struct {
	Offset int64  `json:"offset"`
	Line   string `json:"line"`
}

// Tailer follows the Xray access log, emits completed lines to a callback, and
// performs agent-managed rotation. It is safe to Stop() and re-create.
type Tailer struct {
	path       string
	cursorPath string
	maxBytes   int64

	mu     sync.Mutex
	cursor cursorState

	stopCh chan struct{}
	doneCh chan struct{}

	// canTruncate reports whether the shipper has durably handled everything
	// up to the current offset, so an in-place truncate will not lose data.
	canTruncate func() bool

	// emit receives batches of completed lines.
	emit func([]rawLine)

	// lagBytes exposes how far behind end-of-file the reader is (for status).
	lagBytes int64
}

func NewTailer(path, cursorPath string, maxBytes int64, emit func([]rawLine), canTruncate func() bool) *Tailer {
	return &Tailer{
		path:        path,
		cursorPath:  cursorPath,
		maxBytes:    maxBytes,
		emit:        emit,
		canTruncate: canTruncate,
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
	}
}

func fileIdentity(fi os.FileInfo) (uint64, uint64) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev), uint64(st.Ino)
	}
	return 0, 0
}

func (t *Tailer) loadCursor() {
	data, err := os.ReadFile(t.cursorPath)
	if err != nil {
		return
	}
	var c cursorState
	if json.Unmarshal(data, &c) == nil {
		t.cursor = c
	}
}

func (t *Tailer) saveCursor() {
	t.mu.Lock()
	c := t.cursor
	t.mu.Unlock()
	data, err := json.Marshal(c)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(t.cursorPath), 0755)
	tmp := t.cursorPath + ".tmp"
	if os.WriteFile(tmp, data, 0600) == nil {
		_ = os.Rename(tmp, t.cursorPath)
	}
}

// LagBytes returns how far behind end-of-file the tailer currently is.
func (t *Tailer) LagBytes() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lagBytes
}

func (t *Tailer) Stop() {
	select {
	case <-t.stopCh:
	default:
		close(t.stopCh)
	}
	<-t.doneCh
}

// Run reads new lines in a loop until Stop() is called.
func (t *Tailer) Run() {
	defer close(t.doneCh)
	t.loadCursor()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			t.readAvailable() // final drain
			return
		case <-ticker.C:
			t.readAvailable()
			t.maybeRotate()
		}
	}
}

// readAvailable reads all completed lines currently available and advances the
// cursor. File recreation resets the offset to 0.
func (t *Tailer) readAvailable() {
	fi, err := os.Stat(t.path)
	if err != nil {
		return
	}
	dev, ino := fileIdentity(fi)

	t.mu.Lock()
	// Detect recreation (new inode) or truncation (file shorter than offset).
	if dev != t.cursor.Device || ino != t.cursor.Inode {
		t.cursor = cursorState{Device: dev, Inode: ino, Offset: 0}
	} else if fi.Size() < t.cursor.Offset {
		t.cursor.Offset = 0
	}
	startOffset := t.cursor.Offset
	t.mu.Unlock()

	if fi.Size() <= startOffset {
		t.mu.Lock()
		t.lagBytes = 0
		t.mu.Unlock()
		return
	}

	f, err := os.Open(t.path)
	if err != nil {
		return
	}
	defer f.Close()

	if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
		return
	}

	reader := bufio.NewReader(f)
	offset := startOffset
	batch := make([]rawLine, 0, 256)

	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			// Partial (no trailing newline) — do not consume; wait for the
			// writer to finish the line.
			break
		}
		if err != nil {
			break
		}
		lineStart := offset
		offset += int64(len(line))
		trimmed := line
		if n := len(trimmed); n > 0 && trimmed[n-1] == '\n' {
			trimmed = trimmed[:n-1]
		}
		if len(trimmed) > 0 && trimmed[len(trimmed)-1] == '\r' {
			trimmed = trimmed[:len(trimmed)-1]
		}
		if trimmed == "" {
			continue
		}
		batch = append(batch, rawLine{Offset: lineStart, Line: trimmed})
		if len(batch) >= 1000 {
			t.emit(batch)
			batch = batch[:0]
		}
	}

	if len(batch) > 0 {
		t.emit(batch)
	}

	t.mu.Lock()
	t.cursor.Offset = offset
	t.lagBytes = fi.Size() - offset
	t.mu.Unlock()
	t.saveCursor()
}

// maybeRotate truncates the access log in place once it exceeds the size cap and
// has been fully consumed. Truncating only when size == offset AND the shipper
// has durably handled everything keeps the loss window minimal (smaller than
// logrotate copytruncate) without an external rotation tool.
func (t *Tailer) maybeRotate() {
	fi, err := os.Stat(t.path)
	if err != nil {
		return
	}
	if fi.Size() < t.maxBytes {
		return
	}

	t.mu.Lock()
	fullyRead := fi.Size() == t.cursor.Offset
	t.mu.Unlock()

	if !fullyRead {
		return
	}
	if t.canTruncate != nil && !t.canTruncate() {
		// Shipper still has pending/unacked data; defer truncation.
		return
	}

	if err := os.Truncate(t.path, 0); err != nil {
		log.Printf("[accesslog] truncate failed: %v", err)
		return
	}
	t.mu.Lock()
	t.cursor.Offset = 0
	t.mu.Unlock()
	t.saveCursor()
	log.Printf("[accesslog] rotated access log in place (was %d bytes)", fi.Size())
}
