package multi

import (
	"testing"

	"github.com/jm/security-automation-go/internal/cloudflare/resources"
	"github.com/jm/security-automation-go/internal/snapshot"
)

func TestGraphAssembler_ResolveOrder(t *testing.T) {
	reg := resources.NewRegistry()

	// Create assembler which builds the graph internally
	assembler, err := NewGraphAssembler(reg)
	if err != nil {
		t.Fatalf("failed to create assembler: %v", err)
	}

	// Verify order: Lists must come before ListItems
	listIdx := -1
	listItemIdx := -1

	for i, rt := range assembler.order {
		if rt == snapshot.ResourceLists {
			listIdx = i
		}
		if rt == snapshot.ResourceListItems {
			listItemIdx = i
		}
	}

	if listIdx == -1 || listItemIdx == -1 {
		t.Fatal("expected both Lists and ListItems in order")
	}

	if listIdx > listItemIdx {
		t.Errorf("incorrect order: Lists (%d) should come before ListItems (%d)", listIdx, listItemIdx)
	}
}

func TestGraphAssembler_AddAndBuild(t *testing.T) {
	reg := resources.NewRegistry()
	assembler, _ := NewGraphAssembler(reg)

	// Add list
	err := assembler.Add(snapshot.ResourceLists, []snapshot.NormalizedObject{
		{StableIdentityKey: "list:allowlist", ObjectType: string(snapshot.ResourceLists)},
	})
	if err != nil {
		t.Fatalf("Add lists failed: %v", err)
	}

	// Add items
	err = assembler.Add(snapshot.ResourceListItems, []snapshot.NormalizedObject{
		{StableIdentityKey: "list_item:1.1.1.1", ObjectType: string(snapshot.ResourceListItems)},
	})
	if err != nil {
		t.Fatalf("Add items failed: %v", err)
	}

	snaps, err := assembler.BuildAll()
	if err != nil {
		t.Fatalf("BuildAll failed: %v", err)
	}

	if len(snaps) != len(assembler.order) {
		t.Errorf("expected %d snapshots, got %d", len(assembler.order), len(snaps))
	}
}

func TestGraphAssembler_CycleDetection(t *testing.T) {
	reg := resources.NewRegistry()

	// Force a cycle: List -> Item -> List
	reg.Register(resources.Descriptor{
		Type:         snapshot.ResourceLists,
		Dependencies: []snapshot.ResourceType{snapshot.ResourceListItems},
	})

	_, err := NewGraphAssembler(reg)
	if err == nil {
		t.Fatal("expected error due to cyclic dependency, got nil")
	}
}
