package s3Presign

import (
	"testing"
)

func TestGetCustomKey(t *testing.T) {
	keyAmzMeta := map[string]interface{}{
		"uuid":              "x-amz-meta-uuid",              // less than meta key
		"thisismycha":       "x-amz-meta-thisismycha",       // the same as meta key
		"thisismycharacter": "x-amz-meta-thisismycharacter", // more than meta key

		"x-amz-metauuid":  "x-amz-meta-x-amz-metauuid",
		"x-amz-meta-uuid": "x-amz-meta-uuid",
	}

	for testValue, testResult := range keyAmzMeta {
		result := getCustomKey(testValue, XAmzMetaKey)
		if result != testResult {
			t.Errorf("test value [%s] should be [%s] not [%s]", testValue, testResult, result)
			t.Fail()
		}
	}

	keyAmz := map[string]interface{}{
		"amzkey":            "x-amz-amzkey",            // less than meta key
		"thisismycha":       "x-amz-thisismycha",       // the same as meta key
		"thisismycharacter": "x-amz-thisismycharacter", // more than meta key

		"x-amzamzkey":  "x-amz-x-amzamzkey",
		"x-amz-amzkey": "x-amz-amzkey",
	}

	for testValue, testResult := range keyAmz {
		result := getCustomKey(testValue, XAmzKey)
		if result != testResult {
			t.Errorf("test value [%s] should be [%s] not [%s]", testValue, testResult, result)
			t.Fail()
		}
	}

	if t.Failed() {
		return
	}
}
