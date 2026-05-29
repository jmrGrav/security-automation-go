package pagination

import (
	"context"
	"net/url"
	"strconv"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/cloudflare/models"
)

// Paginator defines how to fetch a single page.
type Paginator[T any] func(ctx context.Context, page int) ([]T, *models.ResultInfo, error)

// TraverseAll fetches all pages of a resource.
func TraverseAll[T any](ctx context.Context, perPage int, fetch Paginator[T]) ([]T, error) {
	const op = "cloudflare.pagination.TraverseAll"
	var all []T

	currentPage := 1
	for {
		items, info, err := fetch(ctx, currentPage)
		if err != nil {
			return nil, apperr.Wrap(op, err)
		}

		all = append(all, items...)

		if info == nil || info.TotalPages == 0 || currentPage >= info.TotalPages {
			break
		}

		// Sanity check: detect infinite loops or invalid pagination from API
		if len(items) == 0 && currentPage < info.TotalPages {
			return nil, apperr.New(op, "API reported more pages but returned empty result")
		}

		currentPage++
	}

	return all, nil
}

// DefaultQuery returns url.Values with page and per_page.
func DefaultQuery(page, perPage int) url.Values {
	q := url.Values{}
	q.Set("page", strconv.Itoa(page))
	q.Set("per_page", strconv.Itoa(perPage))
	return q
}
