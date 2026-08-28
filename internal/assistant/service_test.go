package assistant

import "testing"

func TestRequestedOrderID(t *testing.T) {
	orderID, found := requestedOrderID("What is the status of order #42?")
	if !found || orderID != 42 {
		t.Fatalf("requestedOrderID() = (%d, %t), want (42, true)", orderID, found)
	}
	if _, found := requestedOrderID("Where is my plushie?"); found {
		t.Fatal("requestedOrderID() found an order without an order number")
	}
}
