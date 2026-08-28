package passwords

import "testing"

func TestHashAndVerifyPassword(t *testing.T) {
	passwordHash, err := Hash("password123")
	if err != nil {
		t.Fatal(err)
	}
	if !Verify("password123", passwordHash) {
		t.Fatal("Verify() rejected the password used to create the hash")
	}
	if Verify("wrong-password", passwordHash) {
		t.Fatal("Verify() accepted the wrong password")
	}
}
