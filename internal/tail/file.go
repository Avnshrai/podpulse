// File tailer: opens a CRI log file and emits one Record per line via a
// callback, handling rotation by polling fstat for inode change /
// truncation. No third-party deps — just os + bufio.
package tail

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"syscall"
	"time"
)

// Origin tells the caller where to start reading: from the file head
// (replay history) or from the file's current end (only new lines).
type Origin int

const (
	// FromEnd skips existing content. Use this in production to avoid
	// flooding the detector with already-known templates on restart.
	FromEnd Origin = iota
	// FromBeginning replays the whole file.
	FromBeginning
)

// FileTailer follows a single CRI log file. Goroutine-safe: call Run
// once and Stop to cancel.
type FileTailer struct {
	Path     string
	Origin   Origin
	Emit     func(Record)
	Logger   *slog.Logger
	pollInt  time.Duration
}

// Run blocks until ctx is cancelled or an unrecoverable error occurs.
func (t *FileTailer) Run(ctx context.Context) error {
	if t.Emit == nil {
		return errors.New("tail: Emit callback is nil")
	}
	if t.Logger == nil {
		t.Logger = slog.Default()
	}
	if t.pollInt == 0 {
		t.pollInt = 200 * time.Millisecond
	}

	f, err := os.Open(t.Path)
	if err != nil {
		return err
	}
	defer f.Close()

	if t.Origin == FromEnd {
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			return err
		}
	}

	r := bufio.NewReaderSize(f, 64<<10)
	var partial strings.Builder
	curIno, curSize := statInfo(f)

	tick := time.NewTicker(t.pollInt)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		line, err := r.ReadString('\n')
		if len(line) > 0 {
			line = strings.TrimRight(line, "\r\n")
			if rec, ok := parseCRI(line); ok {
				if criTag(line) == 'P' {
					partial.WriteString(rec.Message)
					continue
				}
				if partial.Len() > 0 {
					rec.Message = partial.String() + rec.Message
					partial.Reset()
				}
				t.Emit(rec)
			}
		}
		if err == io.EOF {
			// Either still tailing (sleep + check rotation) or file gone.
			select {
			case <-ctx.Done():
				return nil
			case <-tick.C:
			}
			ino, sz := statInfo(f)
			rotated := ino == 0 || ino != curIno || sz < curSize
			curIno, curSize = ino, sz

			if rotated {
				newF, err := os.Open(t.Path)
				if err != nil {
					if os.IsNotExist(err) {
						return nil // file deleted; pod gone
					}
					t.Logger.Debug("reopen failed", "path", t.Path, "err", err)
					continue
				}
				_ = f.Close()
				f = newF
				r = bufio.NewReaderSize(f, 64<<10)
				curIno, curSize = statInfo(f)
				partial.Reset()
			}
			continue
		}
		if err != nil {
			return err
		}
	}
}

// statInfo returns (inode, size). Returns (0, 0) on error.
func statInfo(f *os.File) (uint64, int64) {
	fi, err := f.Stat()
	if err != nil {
		return 0, 0
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fi.Size()
	}
	return uint64(st.Ino), fi.Size()
}
