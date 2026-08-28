package acorn

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestReserveHonorsContextAndReturnsReservation(t *testing.T) {
	request := Request{PostalCode: "97001"}
	reservation, err := Reserve(context.Background(), request, 0)
	if err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}
	if reservation.ID != "acorn-97001" {
		t.Errorf("reservation ID = %q", reservation.ID)
	}

	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Reserve(canceledContext, request, time.Second); !errors.Is(err, context.Canceled) {
		t.Errorf("Reserve() cancellation error = %v", err)
	}
}
