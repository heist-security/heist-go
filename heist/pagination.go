package heist

import (
	"context"
	"fmt"
	"iter"
	"net/http"
)

// Paginate yields every item of a page-numbered list operation, requesting
// pages from 1 until total items have been returned or a page is empty.
// fetch returns one page's items and the total count reported by the API.
// Iteration stops after yielding the first error.
func Paginate[T any](ctx context.Context, fetch func(ctx context.Context, page int) (items []T, total int, err error)) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		seen := 0
		for page := 1; ; page++ {
			items, total, err := fetch(ctx, page)
			if err != nil {
				var zero T
				yield(zero, err)
				return
			}
			for _, item := range items {
				if !yield(item, nil) {
					return
				}
			}
			seen += len(items)
			if len(items) == 0 || seen >= total {
				return
			}
		}
	}
}

// AllFindings yields every finding matching params, ignoring params.Page.
func (c *ClientWithResponses) AllFindings(ctx context.Context, params ListFindingsParams) iter.Seq2[Finding, error] {
	return Paginate(ctx, func(ctx context.Context, page int) ([]Finding, int, error) {
		params.Page = &page
		res, err := c.ListFindingsWithResponse(ctx, &params)
		if err != nil {
			return nil, 0, err
		}
		if res.JSON200 == nil {
			return nil, 0, unexpectedResponse(res.HTTPResponse)
		}
		return res.JSON200.Items, res.JSON200.Total, nil
	})
}

// AllApplications yields every application matching params, ignoring params.Page.
func (c *ClientWithResponses) AllApplications(ctx context.Context, params ListApplicationsParams) iter.Seq2[Application, error] {
	return Paginate(ctx, func(ctx context.Context, page int) ([]Application, int, error) {
		params.Page = &page
		res, err := c.ListApplicationsWithResponse(ctx, &params)
		if err != nil {
			return nil, 0, err
		}
		if res.JSON200 == nil {
			return nil, 0, unexpectedResponse(res.HTTPResponse)
		}
		return res.JSON200.Items, res.JSON200.Total, nil
	})
}

// unexpectedResponse reports a 2xx response without the expected JSON body,
// for example one with a non-JSON content type.
func unexpectedResponse(resp *http.Response) error {
	return fmt.Errorf("heist: unexpected %s response with content type %q", resp.Status, resp.Header.Get("Content-Type"))
}
