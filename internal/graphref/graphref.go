// Package graphref holds the Graph client that the rest of the box shares.
//
// The client cannot be a plain field any more: a box is installed before it is
// onboarded, so it starts without one, and the admin UI can create one at any
// time by connecting the tenant. Everything that talks to Graph reads it here
// on each use rather than capturing it once at construction.
package graphref

import (
	"sync"

	"github.com/AcidDemon/m365-cloud-scan/pkg/graph"
)

type Ref struct {
	mu sync.RWMutex
	c  *graph.Client
}

func New(c *graph.Client) *Ref { return &Ref{c: c} }

// Get returns nil while the box is not onboarded. Callers report that as a
// state rather than an error: scans keep queueing until a tenant appears.
func (r *Ref) Get() *graph.Client {
	// A caller that was built without Graph at all holds no reference. That is
	// the same situation as holding one that is empty, so answer it the same way
	// instead of panicking.
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.c
}

func (r *Ref) Set(c *graph.Client) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.c = c
	r.mu.Unlock()
}
