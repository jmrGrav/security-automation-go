package pagination

import (
	"context"
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/cloudflare/models"
)

func TestTraverseAllFetchesAllPagesInOrder(t *testing.T) {
	t.Parallel()

	got, err := TraverseAll(context.Background(), 2, func(_ context.Context, page int) ([]string, *models.ResultInfo, error) {
		switch page {
		case 1:
			return []string{"a", "b"}, &models.ResultInfo{Page: 1, TotalPages: 2}, nil
		case 2:
			return []string{"c"}, &models.ResultInfo{Page: 2, TotalPages: 2}, nil
		default:
			t.Fatalf("unexpected page fetch: %d", page)
			return nil, nil, nil
		}
	})
	if err != nil {
		t.Fatalf("traverse: %v", err)
	}
	if strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("unexpected page order: %+v", got)
	}
}

func TestTraverseAllRejectsEmptyIntermediatePage(t *testing.T) {
	t.Parallel()

	_, err := TraverseAll(context.Background(), 2, func(_ context.Context, page int) ([]string, *models.ResultInfo, error) {
		return nil, &models.ResultInfo{Page: page, TotalPages: 2}, nil
	})
	if err == nil {
		t.Fatal("expected empty intermediate page to fail closed")
	}
}
