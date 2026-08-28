package acorn

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const defaultTimeout = 500 * time.Millisecond

type Request struct {
	Name       string
	Address    string
	City       string
	Region     string
	PostalCode string
}

type Reservation struct {
	ID string
}

func ReserveWithTimeout(ctx context.Context, request Request, delay time.Duration) (Reservation, error) {
	timeoutContext, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	return Reserve(timeoutContext, request, delay)
}

func Reserve(ctx context.Context, request Request, delay time.Duration) (Reservation, error) {
	if delay < 0 {
		return Reservation{}, fmt.Errorf("invalid Acorn fulfillment delay: %s", delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return Reservation{}, ctx.Err()
	case <-timer.C:
		return Reservation{ID: "acorn-" + strings.ToLower(request.PostalCode)}, nil
	}
}
