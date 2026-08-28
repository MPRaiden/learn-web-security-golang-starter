package cart

import "testing"

func TestParseQuantityAcceptsCanonicalValues(t *testing.T) {
	testCases := []struct {
		value   string
		minimum int64
		want    int64
	}{
		{value: "0", minimum: 0, want: 0},
		{value: "1", minimum: 1, want: 1},
		{value: "99", minimum: 1, want: 99},
	}
	for _, testCase := range testCases {
		quantity, valid := parseQuantity(testCase.value, testCase.minimum)
		if !valid || quantity != testCase.want {
			t.Errorf("parseQuantity(%q, %d) = (%d, %t), want (%d, true)", testCase.value, testCase.minimum, quantity, valid, testCase.want)
		}
	}
}

func TestParseQuantityRejectsOutOfRangeValues(t *testing.T) {
	for _, value := range []string{"-1", "100"} {
		if _, valid := parseQuantity(value, 0); valid {
			t.Errorf("parseQuantity(%q, 0) accepted an out-of-range quantity", value)
		}
	}
}
