//go:build windows

package pid

import (
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FindMatching returns a map of process IDs to executable paths for all
// currently running processes that match any of the target executable names.
func FindMatching(targetExes []string) (map[uint32]string, error) {
	pids := make(map[uint32]string)
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = windows.CloseHandle(snapshot) }()

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return nil, err
	}

	for {
		pHandle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, entry.ProcessID)
		if err == nil {
			var buf [1024]uint16
			size := uint32(len(buf))
			err = windows.QueryFullProcessImageName(pHandle, 0, &buf[0], &size)
			_ = windows.CloseHandle(pHandle)
			if err == nil {
				procPath := windows.UTF16ToString(buf[:size])
				if MatchAny(targetExes, procPath) {
					pids[entry.ProcessID] = procPath
				}
			}
		}
		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}
	return pids, nil
}

// MatchAny returns true if the process path matches any of the given targets.
func MatchAny(targetExes []string, procPath string) bool {
	for _, target := range targetExes {
		if MatchTarget(target, procPath) {
			return true
		}
	}
	return false
}

// MatchTarget checks if a process path matches a single target executable name.
func MatchTarget(target, procPath string) bool {
	absTarget, err := filepath.Abs(target)
	if err == nil {
		absTarget = filepath.Clean(absTarget)
		absProc := filepath.Clean(procPath)
		if strings.EqualFold(absProc, absTarget) {
			return true
		}
	}
	if !strings.ContainsAny(target, `/\`) {
		targetBase := filepath.Base(target)
		procBase := filepath.Base(procPath)
		if strings.EqualFold(procBase, targetBase) {
			return true
		}
	}
	return false
}
