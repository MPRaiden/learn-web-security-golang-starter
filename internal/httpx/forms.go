package httpx

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
)

func FormValue(request *http.Request, name string) (string, error) {
	values, exists := request.PostForm[name]
	if !exists {
		return "", nil
	}
	if len(values) != 1 {
		return "", fmt.Errorf("form field %s must occur once", name)
	}
	return values[0], nil
}

func ParseSafeInteger(value string) (int64, bool) {
	parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) || math.Trunc(parsed) != parsed || math.Abs(parsed) > 9_007_199_254_740_991 {
		return 0, false
	}
	return int64(parsed), true
}
