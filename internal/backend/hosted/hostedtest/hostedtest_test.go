package hostedtest_test

import (
	"errors"
	"testing"

	"github.com/enix/tsigoat/internal/backend/hosted/hostedtest"
)

func values(t *testing.T, s *hostedtest.Store[string], zone string) []string {
	t.Helper()
	entries, err := s.Records(zone, nil)
	if err != nil {
		t.Fatal(err)
	}
	list := make([]string, 0, len(entries))
	for _, e := range entries {
		list = append(list, e.Record)
	}
	return list
}

func TestStore(t *testing.T) {
	t.Parallel()
	s := hostedtest.NewStore[string]()
	s.SetZone("example.test", "a", "b")
	if !s.HasZone("example.test") || s.HasZone("other.test") {
		t.Fatal("HasZone() is wrong")
	}

	entries, err := s.Records("example.test", func(r string) bool { return r == "b" })
	if err != nil || len(entries) != 1 {
		t.Fatalf("Records() = %v, %v", entries, err)
	}
	bID := entries[0].ID

	err = s.Update("example.test", func(tx *hostedtest.Tx[string]) error {
		tx.Create("c")
		return tx.Put(bID, "B")
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := values(t, s, "example.test"); len(got) != 3 || got[0] != "a" || got[1] != "B" || got[2] != "c" {
		t.Errorf("after a transaction: %v", got)
	}

	// A failed transaction changes nothing.
	err = s.Update("example.test", func(tx *hostedtest.Tx[string]) error {
		tx.Create("d")
		if deleteErr := tx.Delete(bID); deleteErr != nil {
			return deleteErr
		}
		return tx.Delete("missing")
	})
	if !errors.Is(err, hostedtest.ErrNoRecord) {
		t.Errorf("Update() = %v, want ErrNoRecord", err)
	}
	if got := values(t, s, "example.test"); len(got) != 3 {
		t.Errorf("a failed transaction changed the zone: %v", got)
	}

	if err := s.Update("other.test", func(*hostedtest.Tx[string]) error { return nil }); !errors.Is(err, hostedtest.ErrNoZone) {
		t.Errorf("Update() of a missing zone = %v", err)
	}
	s.DeleteZone("example.test")
	if _, err := s.Records("example.test", nil); !errors.Is(err, hostedtest.ErrNoZone) {
		t.Errorf("Records() of a deleted zone = %v", err)
	}
}
