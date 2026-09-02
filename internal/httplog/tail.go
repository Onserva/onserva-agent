package httplog

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

// tailer follows a log file that another process is writing, and that logrotate
// may replace underneath it at any moment.
//
// Four things it has to survive, all of which happen on a real server:
//   - rotation: the file is renamed and a new one created. The identity at the
//     path changes, so we reopen and read the new file from the start.
//   - truncation: the file is emptied in place (`> access.log`). Same file,
//     but our offset is now past the end.
//   - the log not existing yet: the proxy may not have started, or access
//     logging may not be switched on. Normal, not an error.
//   - a transient read failure: we drop the handle but keep our position, so
//     recovering does not re-count history.
type tailer struct {
	path string
	file *os.File
	// Identity of the file we are following. os.SameFile compares it properly
	// (inode on Unix, file index on Windows), which keeps this package testable
	// off Linux — tests that cannot be run are not much of a safety net.
	identity   os.FileInfo
	offset     int64
	partial    []byte
	everOpened bool
}

func newTailer(path string) *tailer {
	return &tailer{path: path}
}

// maxBytesPerRead caps how much we will read in one pass.
//
// On a very busy server the log can grow faster than we drain it. Reading
// without a ceiling would mean the agent allocating hundreds of megabytes to
// catch up — the monitoring tool becoming the outage. Past the cap we skip
// forward and report how much was passed over, so the gap is visible rather
// than silently changing the numbers.
const maxBytesPerRead = 8 << 20 // 8 MiB

// readLines returns the complete lines written since the last call.
//
// A trailing partial line is held back and prepended next time: the proxy may
// well be halfway through writing it.
func (t *tailer) readLines() (lines [][]byte, skippedBytes int64, err error) {
	if err := t.ensureOpen(); err != nil {
		return nil, 0, err
	}
	if t.file == nil {
		return nil, 0, nil // log not present or not readable yet
	}

	info, err := t.file.Stat()
	if err != nil {
		t.dropHandle()
		return nil, 0, fmt.Errorf("stat access log: %w", err)
	}

	size := info.Size()
	if size < t.offset {
		// Truncated in place. Start again from the beginning.
		t.offset = 0
		t.partial = nil
	}

	pending := size - t.offset
	if pending <= 0 {
		return nil, 0, nil
	}

	if pending > maxBytesPerRead {
		skippedBytes = pending - maxBytesPerRead
		t.offset = size - maxBytesPerRead
		t.partial = nil
	}

	if _, err := t.file.Seek(t.offset, io.SeekStart); err != nil {
		t.dropHandle()
		return nil, skippedBytes, fmt.Errorf("seek access log: %w", err)
	}

	buffer := make([]byte, size-t.offset)
	read, err := io.ReadFull(t.file, buffer)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		t.dropHandle()
		return nil, skippedBytes, fmt.Errorf("read access log: %w", err)
	}
	buffer = buffer[:read]
	t.offset += int64(read)

	if len(t.partial) > 0 {
		buffer = append(t.partial, buffer...)
		t.partial = nil
	}

	segments := bytes.Split(buffer, []byte{'\n'})
	// The final segment has no newline yet: hold it until the writer finishes.
	if last := segments[len(segments)-1]; len(last) > 0 {
		t.partial = append([]byte(nil), last...)
	}
	segments = segments[:len(segments)-1]

	return segments, skippedBytes, nil
}

// ensureOpen opens the log if needed, and reopens it after a rotation.
func (t *tailer) ensureOpen() error {
	info, err := os.Stat(t.path)
	if err != nil {
		// Missing or unreadable. Drop the handle but keep our position: the
		// proxy may be mid-rotation, or not started yet.
		t.dropHandle()
		if os.IsNotExist(err) || os.IsPermission(err) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", t.path, err)
	}

	sameFile := t.identity != nil && os.SameFile(info, t.identity)
	if t.file != nil && sameFile {
		return nil // same file, still following it
	}
	t.dropHandle()

	file, err := os.Open(t.path)
	if err != nil {
		if os.IsPermission(err) {
			return nil // surfaced once by the caller, never fatal
		}
		return fmt.Errorf("open %s: %w", t.path, err)
	}
	t.file = file

	switch {
	case !t.everOpened:
		// First open since the agent started. Begin at the END: parsing a
		// gigabyte of history would be pointless work, and would report a burst
		// of last week's traffic as if it were happening now.
		t.everOpened = true
		if end, err := file.Seek(0, io.SeekEnd); err == nil {
			t.offset = end
		}
		t.partial = nil
	case !sameFile:
		// Rotated. The new file starts at zero.
		t.offset = 0
		t.partial = nil
	}

	t.identity = info
	return nil
}

// dropHandle closes the file but keeps our position, so a transient failure
// does not cause the backlog to be counted twice.
func (t *tailer) dropHandle() {
	if t.file != nil {
		_ = t.file.Close()
		t.file = nil
	}
}
