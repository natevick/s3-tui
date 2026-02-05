package security

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestValidBookmarkName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid simple", "my-bookmark", false},
		{"valid with spaces", "my bookmark", false},
		{"valid with dots", "my.bookmark", false},
		{"valid with slashes", "my/bookmark", false},
		{"empty", "", true},
		{"too long", string(make([]byte, 300)), true},
		{"invalid chars", "my<>bookmark", true},
		{"invalid semicolon", "my;bookmark", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidBookmarkName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidBookmarkName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidProfileName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid simple", "my-profile", false},
		{"valid with underscore", "my_profile", false},
		{"valid numbers", "profile123", false},
		{"empty allowed", "", false},
		{"too long", string(make([]byte, 200)), true},
		{"invalid spaces", "my profile", true},
		{"invalid dots", "my.profile", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidProfileName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidProfileName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidBucketName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid simple", "my-bucket", false},
		{"valid with dots", "my.bucket.name", false},
		{"valid numbers", "bucket123", false},
		{"empty allowed", "", false},
		{"too short", "ab", true},
		{"too long", string(make([]byte, 70)), true},
		{"invalid uppercase", "My-Bucket", true},
		{"invalid underscore", "my_bucket", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidBucketName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidBucketName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestSafePath(t *testing.T) {
	// Create temp directory for tests
	tmpDir, err := os.MkdirTemp("", "safepath-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		name     string
		baseDir  string
		relPath  string
		wantErr  bool
		contains string // error should contain this string
	}{
		{"valid simple", tmpDir, "file.txt", false, ""},
		{"valid nested", tmpDir, "a/b/c/file.txt", false, ""},
		{"path traversal dotdot", tmpDir, "../etc/passwd", true, "traversal"},
		{"path traversal hidden", tmpDir, "a/../../etc/passwd", true, "traversal"},
		{"path traversal absolute", tmpDir, "/etc/passwd", true, ""},
		{"dangerous dev", tmpDir, "dev/null", true, "system"},
		{"dangerous proc", tmpDir, "a/proc/self", true, "system"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SafePath(tt.baseDir, tt.relPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("SafePath(%q, %q) error = %v, wantErr %v", tt.baseDir, tt.relPath, err, tt.wantErr)
				return
			}
			if err != nil && tt.contains != "" {
				if !contains(err.Error(), tt.contains) {
					t.Errorf("SafePath(%q, %q) error = %q, want contains %q", tt.baseDir, tt.relPath, err.Error(), tt.contains)
				}
			}
			if err == nil {
				// Verify path is within base directory
				absBase, _ := filepath.Abs(tt.baseDir)
				if !hasPrefix(result, absBase) {
					t.Errorf("SafePath result %q is not within base %q", result, absBase)
				}
			}
		})
	}
}

func TestSanitizeError(t *testing.T) {
	tests := []struct {
		name     string
		input    error
		notWant  string // should NOT contain this
	}{
		{"nil error", nil, ""},
		{"account id", errors.New("Error for account 123456789012"), "123456789012"},
		{"arn", errors.New("Error with arn:aws:s3:::my-bucket/key"), "arn:aws"},
		{"access key", errors.New("Invalid key AKIAIOSFODNN7EXAMPLE"), "AKIAIOSFODNN7EXAMPLE"},
		{"home path", errors.New("File /home/johndoe/secret.txt not found"), "johndoe"},
		{"users path", errors.New("File /Users/johndoe/secret.txt not found"), "johndoe"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeError(tt.input)
			if tt.notWant != "" && contains(result, tt.notWant) {
				t.Errorf("SanitizeError() = %q, should not contain %q", result, tt.notWant)
			}
		})
	}
}

func TestSanitizeErrorGeneric(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		context string
		want    string
	}{
		{"access denied", errors.New("AccessDenied: you cannot"), "Loading", "Loading: access denied"},
		{"expired token", errors.New("token has expired"), "Auth", "Auth: credentials expired"},
		{"connection error", errors.New("connection refused"), "API", "API: connection error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeErrorGeneric(tt.err, tt.context)
			if !contains(result, tt.want) {
				t.Errorf("SanitizeErrorGeneric() = %q, want contains %q", result, tt.want)
			}
		})
	}
}

// Helper functions
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
