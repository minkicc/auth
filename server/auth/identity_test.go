package auth

import "testing"

func TestNormalizeAccountID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "trim spaces", input: "  demo.user  ", want: "demo.user"},
		{name: "allow uppercase", input: "Demo_User", want: "Demo_User"},
		{name: "reject too short", input: "ab", wantErr: true},
		{name: "reject invalid char", input: "demo/user", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeAccountID(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got normalized account id %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeAccountID(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeEmailAddress(t *testing.T) {
	got, err := NormalizeEmailAddress("  USER@Example.COM  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "user@example.com" {
		t.Fatalf("NormalizeEmailAddress returned %q", got)
	}

	if _, err := NormalizeEmailAddress("invalid-email"); err == nil {
		t.Fatalf("expected invalid email to be rejected")
	}
}

func TestNormalizePhoneNumber(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "keep plain digits", input: "13800138000", want: "13800138000"},
		{name: "normalize separators", input: "+86 138-0013-8000", want: "+8613800138000"},
		{name: "reject letters", input: "13800abc000", wantErr: true},
		{name: "reject too short", input: "12345", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizePhoneNumber(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got normalized phone %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("NormalizePhoneNumber(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
