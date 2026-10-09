package cache

import (
	"reflect"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	c := New(t.TempDir())
	recs := []Record{
		{Vaddr: 0x1000, Hex: "5fc3", Frame: []bool{false, true}},
		{Vaddr: 0x2000, Hex: "c3", Frame: nil},
	}
	key, err := c.Key(FileHash([]byte("abc")), map[string]any{"depth": 5, "flags": 4})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Store(key, recs); err != nil {
		t.Fatal(err)
	}
	got, ok := c.Load(key)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if !reflect.DeepEqual(got, recs) {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", got, recs)
	}
}

func TestKeyStableAndSensitive(t *testing.T) {
	c := New(t.TempDir())
	k1, _ := c.Key("h", map[string]any{"depth": 5})
	k2, _ := c.Key("h", map[string]any{"depth": 5})
	k3, _ := c.Key("h", map[string]any{"depth": 6})
	if k1 != k2 {
		t.Error("key not stable for identical input")
	}
	if k1 == k3 {
		t.Error("key not sensitive to params")
	}
}

func TestMiss(t *testing.T) {
	c := New(t.TempDir())
	if _, ok := c.Load("nonexistent"); ok {
		t.Error("expected miss")
	}
}
