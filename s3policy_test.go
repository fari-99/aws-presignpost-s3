package s3

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// this is for testing purposes, if you decided to use it for real
// please change all value here with your Aws Credentials
// comment line
const AWSAccessKeyId = "AKIAIOSFODNN7EXAMPLE"
const AWSSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
const AWSRegion = "us-east-1"
const AwsBucket = "sigv4examplebucket"
const SecurityTokenUser = "eW91dHViZQ=="
const SecurityTokenProduct = "b0hnNVNKWVJIQTA="

const htmlTestLocation = "./"
const htmlTestFileName = "generate_html.html"

type DefaultTestData struct {
	AwsConfig             AwsConfig
	DateCreated           time.Time
	TimeExpired           time.Time
	Acl                   string
	StartRange            uint64
	StopRange             uint64
	CacheControl          string
	ContentType           string
	ContentDisposition    string
	ContentEncoding       string
	Key                   string
	SuccessActionRedirect string
	SuccessActionStatus   string
	UserToken             string
	ProductToken          string
	Uuid                  string
	Tag                   string
	SSE                   string
}

func getDefaultData() DefaultTestData {
	dateCreated, _ := time.Parse(SignatureDateFormat, "20151229")
	timeExpired, _ := time.Parse(ExpirationFormat, "2015-12-30T12:00:00.000Z")

	awsConfig := AwsConfig{
		AwsAccessKey: AWSAccessKeyId,
		AwsRegion:    AWSRegion,
		AwsSecretKey: AWSSecretAccessKey,
		AwsBucket:    AwsBucket,
	}

	defaultData := DefaultTestData{
		AwsConfig:   awsConfig,
		DateCreated: dateCreated,
		TimeExpired: timeExpired,

		Acl:                   "public-read",
		Key:                   "user/user1/test.jpeg",
		SuccessActionRedirect: fmt.Sprintf("https://%s.s3.amazonaws.com/successful_upload.html", AwsBucket),
		SuccessActionStatus:   "204",

		StartRange:         0,        // 0 byte
		StopRange:          10485760, // 10 MiB
		CacheControl:       "no-cache",
		ContentType:        "image/jpeg",
		ContentDisposition: "Attachment; filename=test.jpeg",
		ContentEncoding:    "token",

		UserToken:    SecurityTokenUser,
		ProductToken: SecurityTokenProduct,

		Uuid: "bc2035bf-72b6-4bad-9e1f-c6c8732ac1a4",
		Tag:  "",
		SSE:  "AES256",
	}

	return defaultData
}

func TestS3Signature(t *testing.T) {
	policy := `{
  "expiration": "2015-12-30T12:00:00.000Z",
  "conditions": [
    {"x-amz-server-side-encryption": "AES256"},
    ["starts-with","$x-amz-meta-tag",""],
    {"x-amz-meta-uuid": "bc2035bf-72b6-4bad-9e1f-c6c8732ac1a4"},
    {"success_action_redirect": "https://sigv4examplebucket.s3.amazonaws.com/successful_upload.html"},
    {"x-amz-credential": "AKIAIOSFODNN7EXAMPLE/20151229/us-east-1/s3/aws4_request"},
    {"acl": "public-read"},
    {"Content-Type": "image/jpeg"},
    {"x-amz-date": "20151229T000000Z"},
    {"bucket": "sigv4examplebucket"},
    {"Expires": "2015-12-30T12:00:00.000Z"},
    {"key": "user/user1/test.jpeg"},
    {"x-amz-algorithm": "AWS4-HMAC-SHA256"}
  ]
}`
	encodedValue := "ewogICJleHBpcmF0aW9uIjogIjIwMTUtMTItMzBUMTI6MDA6MDAuMDAwWiIsCiAgImNvbmRpdGlvbnMiOiBbCiAgICB7I" +
		"ngtYW16LXNlcnZlci1zaWRlLWVuY3J5cHRpb24iOiAiQUVTMjU2In0sCiAgICBbInN0YXJ0cy13aXRoIiwiJHgtYW16LW1ldGEtdGFnIi" +
		"wiIl0sCiAgICB7IngtYW16LW1ldGEtdXVpZCI6ICJiYzIwMzViZi03MmI2LTRiYWQtOWUxZi1jNmM4NzMyYWMxYTQifSwKICAgIHsic3V" +
		"jY2Vzc19hY3Rpb25fcmVkaXJlY3QiOiAiaHR0cHM6Ly9zaWd2NGV4YW1wbGVidWNrZXQuczMuYW1hem9uYXdzLmNvbS9zdWNjZXNzZnVs" +
		"X3VwbG9hZC5odG1sIn0sCiAgICB7IngtYW16LWNyZWRlbnRpYWwiOiAiQUtJQUlPU0ZPRE5ON0VYQU1QTEUvMjAxNTEyMjkvdXMtZWFzd" +
		"C0xL3MzL2F3czRfcmVxdWVzdCJ9LAogICAgeyJhY2wiOiAicHVibGljLXJlYWQifSwKICAgIHsiQ29udGVudC1UeXBlIjogImltYWdlL2" +
		"pwZWcifSwKICAgIHsieC1hbXotZGF0ZSI6ICIyMDE1MTIyOVQwMDAwMDBaIn0sCiAgICB7ImJ1Y2tldCI6ICJzaWd2NGV4YW1wbGVidWN" +
		"rZXQifSwKICAgIHsiRXhwaXJlcyI6ICIyMDE1LTEyLTMwVDEyOjAwOjAwLjAwMFoifSwKICAgIHsia2V5IjogInVzZXIvdXNlcjEvdGVz" +
		"dC5qcGVnIn0sCiAgICB7IngtYW16LWFsZ29yaXRobSI6ICJBV1M0LUhNQUMtU0hBMjU2In0KICBdCn0="

	signatureValue := "93f964fe2e23b72975e4751526bc422b5a609ede3d1a9f3d0dc8288da646a9e2"

	defaultData := getDefaultData()

	s3PolicyBase := NewS3Policy(defaultData.AwsConfig)
	s3PolicyBase.Date = defaultData.DateCreated
	s3PolicyBase.SetExpirationDate(defaultData.TimeExpired)

	encodedPolicy := s3PolicyBase.encodePolicy([]byte(policy))
	signature := s3PolicyBase.generateSignature(encodedPolicy)

	if encodedPolicy != encodedValue {
		t.Log("encoded policy is not the same")
	}

	if signature != signatureValue {
		t.Log("signature is not correct")
	}
}

func TestGenerateHtml(t *testing.T) {
	testKeyValue := map[string]string{
		"bucket":                       "sigv4examplebucket",
		"key":                          "user/user1/test.jpeg",
		"x-amz-algorithm":              "AWS4-HMAC-SHA256",
		"x-amz-credential":             "AKIAIOSFODNN7EXAMPLE/20151229/us-east-1/s3/aws4_request",
		"x-amz-date":                   "20151229T000000Z",
		"acl":                          "public-read",
		"Cache-Control":                "no-cache",
		"Content-Type":                 "image/jpeg",
		"Content-Disposition":          "Attachment; filename=test.jpeg",
		"Content-Encoding":             "token",
		"Expires":                      "Wed, 30 Dec 2015 12:00:00 UTC",
		"success_action_redirect":      "https://sigv4examplebucket.s3.amazonaws.com/successful_upload.html",
		"success_action_status":        "204",
		"x-amz-server-side-encryption": "AES256",
		"x-amz-meta-tag":               "",
		"x-amz-meta-uuid":              "bc2035bf-72b6-4bad-9e1f-c6c8732ac1a4",
		"x-amz-security-token":         "eW91dHViZQ==,b0hnNVNKWVJIQTA=",
		// signature, and encoded policy tested on function TestS3Signature()
	}

	defaultData := getDefaultData()
	s3PolicyBase := NewS3Policy(defaultData.AwsConfig)
	s3PolicyBase.Date = defaultData.DateCreated
	s3PolicyBase.SetExpirationDate(defaultData.TimeExpired)

	// this policy will be generated by default (because must have in the html)
	// don't need to uncomment it.
	// s3PolicyBase.SetBucketPolicy(ConditionMatchingExactMatch, defaultData.AwsConfig.AwsBucket)
	// s3PolicyBase.setXAmzDatePolicy()
	// s3PolicyBase.setXAmzCredentialPolicy()
	// s3PolicyBase.setXAmzAlgorithmPolicy()
	// policy (generated with s3PolicyBase.GeneratePolicy())
	// x-amz-signature (generated with s3PolicyBase.GeneratePolicy())

	s3PolicyBase.SetAclPolicy(ConditionMatchingExactMatch, defaultData.Acl)
	s3PolicyBase.SetContentLengthPolicy(defaultData.StartRange, defaultData.StopRange)
	s3PolicyBase.SetKeyPolicy(ConditionMatchingExactMatch, defaultData.Key)
	s3PolicyBase.SetSuccessActionRedirectPolicy(ConditionMatchingExactMatch, defaultData.SuccessActionRedirect)
	s3PolicyBase.SetSuccessActionStatusPolicy(ConditionMatchingStartWith, defaultData.SuccessActionStatus)
	s3PolicyBase.SetXAmzSecurityTokenPolicy(ConditionMatchingExactMatch, defaultData.UserToken, defaultData.ProductToken)

	// rest api
	s3PolicyBase.SetCacheControlPolicy(ConditionMatchingStartWith, defaultData.CacheControl)              // https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9
	s3PolicyBase.SetContentTypePolicy(ConditionMatchingExactMatch, defaultData.ContentType)               // https://www.rfc-editor.org/rfc/rfc9110.html#name-content-type
	s3PolicyBase.SetContentDispositionPolicy(ConditionMatchingExactMatch, defaultData.ContentDisposition) // https://www.rfc-editor.org/rfc/rfc6266#section-4
	s3PolicyBase.SetContentEncodingPolicy(ConditionMatchingExactMatch, defaultData.ContentEncoding)       // https://www.rfc-editor.org/rfc/rfc9110.html#field.content-encoding
	s3PolicyBase.SetExpiresPolicy(defaultData.TimeExpired)                                                // https://www.rfc-editor.org/rfc/rfc7234#section-5.3

	// custom key
	s3PolicyBase.SetXAmzMeta("uuid", ConditionMatchingExactMatch, defaultData.Uuid)
	s3PolicyBase.SetXAmzMeta("tag", ConditionMatchingStartWith, defaultData.Tag)

	// amazon key
	s3PolicyBase.SetXAmz("x-amz-server-side-encryption", ConditionMatchingExactMatch, defaultData.SSE)

	_, _, formsData := s3PolicyBase.GeneratePolicy()
	for _, value := range formsData.FormData {
		if value.FormName == "policy" || value.FormName == "x-amz-signature" {
			continue // don't need to check
		}

		if valueTest, ok := testKeyValue[value.FormName]; !ok || valueTest != value.FormValue {
			keyMessage := fmt.Sprintf("key [%s] not found in test data", value.FormName)
			valueMessage := fmt.Sprintf("value [%s] should be [%s]", value.FormValue, valueTest)
			t.Log(fmt.Sprintf("error key or error value: \n %s \n %s", keyMessage, valueMessage))
			t.Fail()
		}
	}

	if t.Failed() {
		return
	}

	// uncomment if you want to test generated policy to AWS
	generateHtml(formsData)
}

func generateHtml(formsData Forms) {
	htmlDocument, err := GenerateFormHtml(formsData)
	if err != nil {
		panic(err.Error())
		return
	}

	fileCreate, err := os.Create(fmt.Sprintf("%s%s", htmlTestLocation, htmlTestFileName))
	if err != nil {
		panic(err.Error())
		return
	}

	defer fileCreate.Close()

	_, err = fileCreate.WriteString(htmlDocument)

	if err != nil {
		panic(err.Error())
		return
	}
}
