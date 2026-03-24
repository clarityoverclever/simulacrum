package responder

import (
	"context"
	"testing"
	"time"
)

func TestMemoryStore(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	key := Key("test-key")

	// Test Get on empty store
	_, ok := store.Get(ctx, key)
	if ok {
		t.Error("Expected Get to return false for non-existent key")
	}

	// Test GetOrCreate
	record, err := store.GetOrCreate(ctx, key)
	if err != nil {
		t.Fatalf("GetOrCreate failed: %v", err)
	}
	if record.Key != key {
		t.Errorf("Expected key %s, got %s", key, record.Key)
	}

	// Test Get after creation
	record, ok = store.Get(ctx, key)
	if !ok {
		t.Error("Expected Get to return true after creation")
	}

	// Test UpdateMeta
	meta := map[string]string{"foo": "bar"}
	record, err = store.UpdateMeta(ctx, key, meta)
	if err != nil {
		t.Fatalf("UpdateMeta failed: %v", err)
	}
	if record.Meta["foo"] != "bar" {
		t.Errorf("Expected meta foo=bar, got %s", record.Meta["foo"])
	}

	// Test AddTag
	tag := "test-tag"
	record, err = store.AddTag(ctx, key, tag)
	if err != nil {
		t.Fatalf("AddTag failed: %v", err)
	}
	if _, ok := record.Tags[tag]; !ok {
		t.Error("Expected tag to be present")
	}

	// Test RemoveTag
	record, err = store.RemoveTag(ctx, key, tag)
	if err != nil {
		t.Fatalf("RemoveTag failed: %v", err)
	}
	if _, ok := record.Tags[tag]; ok {
		t.Error("Expected tag to be removed")
	}

	// Test MarkSeen
	now := time.Now().Truncate(time.Second)
	record, err = store.MarkSeen(ctx, key, now)
	if err != nil {
		t.Fatalf("MarkSeen failed: %v", err)
	}
	if !record.LastSeen.Equal(now) {
		t.Errorf("Expected LastSeen %v, got %v", now, record.LastSeen)
	}

	// Test Observe
	obs := Observation{
		Kind:      KindDNS,
		Timestamp: now.Add(time.Minute),
		Meta:      map[string]string{"new": "meta"},
	}
	record, err = store.Observe(ctx, key, obs)
	if err != nil {
		t.Fatalf("Observe failed: %v", err)
	}
	if record.DNSQueries != 1 {
		t.Errorf("Expected 1 DNS query, got %d", record.DNSQueries)
	}
	if record.Meta["new"] != "meta" {
		t.Errorf("Expected meta new=meta, got %s", record.Meta["new"])
	}

	// Test PruneExpired
	count, err := store.PruneExpired(ctx, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("PruneExpired failed: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 record pruned, got %d", count)
	}

	_, ok = store.Get(ctx, key)
	if ok {
		t.Error("Expected record to be pruned")
	}

	// Test Delete
	store.GetOrCreate(ctx, key)
	err = store.Delete(ctx, key)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	_, ok = store.Get(ctx, key)
	if ok {
		t.Error("Expected record to be deleted")
	}
}
