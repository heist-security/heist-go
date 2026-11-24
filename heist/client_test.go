package heist

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) *ClientWithResponses {
	t.Helper()
	return newTestClientWithTokens(t, StaticToken("test-token"), handler)
}

func newTestClientWithTokens(t *testing.T, tokens TokenSource, handler http.HandlerFunc) *ClientWithResponses {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := New(tokens, Config{
		ServerURL:  server.URL + "/external",
		HTTPClient: server.Client(),
		UserAgent:  "heist-test/1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprint(w, body)
}

func TestClientSendsAuthAndUserAgent(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/external/findings/counts" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != "heist-test/1.0 heist-go" {
			t.Errorf("User-Agent = %q", got)
		}
		writeJSON(w, http.StatusOK, `{"all":5,"open":3,"closed":2,"accepted":1,"compensatingControl":1}`)
	})

	res, err := client.FindingCountsWithResponse(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.JSON200.All != 5 || res.JSON200.Open != 3 {
		t.Errorf("counts = %+v", res.JSON200)
	}
}

func TestClientReturnsAPIErrors(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, `{"error":{"code":"not_found","message":"Finding not found"}}`)
	})

	_, err := client.FindingCountsWithResponse(context.Background())
	if !IsNotFound(err) {
		t.Fatalf("IsNotFound(%v) = false", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error %T is not *APIError", err)
	}
	if apiErr.Code != "not_found" || apiErr.Message != "Finding not found" {
		t.Errorf("error = %+v", apiErr)
	}
}

func TestClientHandlesNonEnvelopeErrors(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "<html>Bad gateway</html>", http.StatusBadGateway)
	})

	_, err := client.FindingCountsWithResponse(context.Background())
	if StatusCode(err) != http.StatusBadGateway {
		t.Fatalf("StatusCode(%v) = %d, want 502", err, StatusCode(err))
	}
	if got := err.Error(); got != "heist: HTTP 502 Bad Gateway" {
		t.Errorf("Error() = %q", got)
	}
}

func TestStatusCodeIgnoresOtherErrors(t *testing.T) {
	if got := StatusCode(errors.New("network down")); got != 0 {
		t.Errorf("StatusCode = %d, want 0", got)
	}
}

func TestEmptyTokenFailsBeforeSending(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request sent without a token")
	}))
	t.Cleanup(server.Close)
	client, err := New(StaticToken(""), Config{ServerURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.FindingCountsWithResponse(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

// Additive API releases add fields and enum values. Released SDK versions must
// keep decoding those responses.
func TestClientToleratesAdditiveChanges(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, `{"page":1,"size":1,"total":1,"items":[{
			"id":"f1","title":"t","description":"d","type":"t","category":"c",
			"severity":"HIGH","validationStatus":"PUBLISHED","createdAt":"2026-01-01T00:00:00Z",
			"applicationId":null,"routeId":null,"issueMetadata":null,
			"sourceKind":"some_future_kind","someFutureField":1}]}`)
	})

	res, err := client.ListFindingsWithResponse(context.Background(), &ListFindingsParams{})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.JSON200.Items[0].SourceKind; got != "some_future_kind" {
		t.Errorf("SourceKind = %q", got)
	}
}

func TestAllFindingsPaginates(t *testing.T) {
	const total = 5
	var pages []string
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		pages = append(pages, r.URL.Query().Get("page"))
		if got := r.URL.Query().Get("size"); got != "2" {
			t.Errorf("size = %q, want 2", got)
		}
		var items []Finding
		for i := (page - 1) * 2; i < min(page*2, total); i++ {
			items = append(items, Finding{Id: fmt.Sprintf("finding-%d", i), Severity: FindingSeverityHIGH})
		}
		body, err := json.Marshal(map[string]any{"page": page, "size": 2, "total": total, "items": items})
		if err != nil {
			t.Error(err)
		}
		writeJSON(w, http.StatusOK, string(body))
	})

	size := 2
	var ids []string
	for finding, err := range client.AllFindings(context.Background(), ListFindingsParams{Size: &size}) {
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, finding.Id)
	}
	if len(ids) != total || ids[0] != "finding-0" || ids[total-1] != "finding-4" {
		t.Errorf("ids = %v", ids)
	}
	if fmt.Sprint(pages) != "[1 2 3]" {
		t.Errorf("requested pages %v, want [1 2 3]", pages)
	}
}

func TestAllFindingsReturnsAPIErrors(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusForbidden, `{"error":{"code":"forbidden","message":"Viewer role required"}}`)
	})
	for _, err := range client.AllFindings(context.Background(), ListFindingsParams{}) {
		if StatusCode(err) != http.StatusForbidden {
			t.Fatalf("err = %v, want 403", err)
		}
		return
	}
	t.Fatal("iterator yielded nothing")
}

func TestPaginateStopsOnError(t *testing.T) {
	calls := 0
	fetch := func(ctx context.Context, page int) ([]int, int, error) {
		calls++
		if page == 2 {
			return nil, 0, errors.New("boom")
		}
		return []int{1, 2}, 10, nil
	}
	var got []int
	var gotErr error
	for item, err := range Paginate(context.Background(), fetch) {
		if err != nil {
			gotErr = err
			break
		}
		got = append(got, item)
	}
	if gotErr == nil || len(got) != 2 || calls != 2 {
		t.Errorf("items %v, err %v, calls %d", got, gotErr, calls)
	}
}
