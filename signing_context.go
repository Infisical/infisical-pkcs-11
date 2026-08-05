package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"
)

const maxCommandLen = 2048

const redactedValue = "***"

var secretCommandFlags = map[string]bool{
	"storepass":  true,
	"keypass":    true,
	"pass":       true,
	"passin":     true,
	"passout":    true,
	"password":   true,
	"passphrase": true,
	"pin":        true,
	"p":          true,
	"pw":         true,
}

func flagName(token string) string {
	var trimmed string
	switch {
	case strings.HasPrefix(token, "--"):
		trimmed = token[2:]
	case strings.HasPrefix(token, "-"), strings.HasPrefix(token, "/"):
		trimmed = token[1:]
	default:
		return ""
	}
	return strings.ToLower(trimmed)
}

func hasSecretSuffix(name string) bool {
	return strings.HasSuffix(name, "password") ||
		strings.HasSuffix(name, "passphrase") ||
		strings.HasSuffix(name, "passwd")
}

func isSecretFlagName(name string, hasInlineValue bool) bool {
	if name == "" {
		return false
	}
	if secretCommandFlags[name] || hasSecretSuffix(name) {
		return true
	}
	if !hasInlineValue {
		return false
	}
	subKey := name[strings.LastIndexAny(name, ":._")+1:]
	return secretCommandFlags[subKey] || hasSecretSuffix(subKey)
}

func redactCommandArgs(args []string) []string {
	redacted := slices.Clone(args)

	redactValue := false
	for i, arg := range redacted {
		key, _, hasInlineValue := strings.Cut(arg, "=")
		name := flagName(key)
		if name == "" && hasInlineValue {
			name = strings.ToLower(key)
		}
		isSecret := isSecretFlagName(name, hasInlineValue)

		if redactValue {
			redactValue = false
			if !isSecret {
				redacted[i] = redactedValue
				continue
			}
		}

		if isSecret {
			if hasInlineValue {
				redacted[i] = key + "=" + redactedValue
			} else {
				redactValue = true
			}
			continue
		}

		// "-pass:secret" carries its value in the same token after the colon.
		if colon := strings.Index(arg, ":"); colon > 0 && !hasInlineValue {
			if prefix := flagName(arg[:colon]); isSecretFlagName(prefix, false) {
				redacted[i] = arg[:colon+1] + redactedValue
			}
		}
	}
	return redacted
}

func joinCommandArgs(args []string) string {
	rendered := make([]string, len(args))
	for i, arg := range args {
		switch {
		case arg == "":
			rendered[i] = `""`
		case strings.ContainsAny(arg, " \t"):
			rendered[i] = `"` + arg + `"`
		default:
			rendered[i] = arg
		}
	}
	return strings.Join(rendered, " ")
}

func truncateCommand(command string) string {
	if len(command) <= maxCommandLen {
		return command
	}
	cut := maxCommandLen
	for cut > 0 && !utf8.RuneStart(command[cut]) {
		cut--
	}
	return command[:cut]
}

type signingContext struct {
	Command         string
	Application     string
	ApplicationHash string
	Hostname        string
	OSUsername      string
}

var (
	signingCtx     signingContext
	signingCtxOnce sync.Once
)

func currentSigningContext() signingContext {
	signingCtxOnce.Do(func() {
		if exe, err := os.Executable(); err == nil {
			signingCtx.Application = filepath.Base(exe)
			signingCtx.ApplicationHash = fileSHA256(exe)
		}
		signingCtx.Command = truncateCommand(joinCommandArgs(redactCommandArgs(processCommandLine())))
		signingCtx.Hostname, _ = os.Hostname()
		if u, err := user.Current(); err == nil {
			signingCtx.OSUsername = u.Username
		}
	})
	return signingCtx
}

type clientMetadata struct {
	Tool                   string `json:"tool,omitempty"`
	SigningApplicationHash string `json:"signingApplicationHash,omitempty"`
	Hostname               string `json:"hostname,omitempty"`
	OSUsername             string `json:"osUsername,omitempty"`
	Command                string `json:"command,omitempty"`
	ModuleVersion          string `json:"moduleVersion,omitempty"`
}

type signingScope struct {
	Command                string `json:"command,omitempty"`
	SigningApplication     string `json:"signingApplication,omitempty"`
	SigningApplicationHash string `json:"signingApplicationHash,omitempty"`
	Hostname               string `json:"hostname,omitempty"`
	OSUsername             string `json:"osUsername,omitempty"`
	DataHash               string `json:"dataHash,omitempty"`
}

func (c signingContext) clientMetadata() clientMetadata {
	return clientMetadata{
		Tool:                   c.Application,
		SigningApplicationHash: c.ApplicationHash,
		Hostname:               c.Hostname,
		OSUsername:             c.OSUsername,
		Command:                c.Command,
	}
}

func (c signingContext) requestScope(dataHash string) signingScope {
	return signingScope{
		Command:                c.Command,
		SigningApplication:     c.Application,
		SigningApplicationHash: c.ApplicationHash,
		Hostname:               c.Hostname,
		OSUsername:             c.OSUsername,
		DataHash:               dataHash,
	}
}

func fileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
