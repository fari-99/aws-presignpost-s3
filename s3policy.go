package s3Presign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

// All condition matching detail can be checked here
// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html#sigv4-ConditionMatching
const ConditionMatchingExactMatch = "eq"
const ConditionMatchingStartWith = "starts-with"
const ConditionSpecifyingRange = "content-length-range"

const ExpirationFormat = "2006-01-02T15:04:05.000Z"
const SignatureDateFormat = "20060102"
const AmzDateFormat = "20060102T150405Z"
const ExpiredHeaderFormat = "Mon, 02 Jan 2006 15:04:05 MST"

const AmzAlgorithm = "AWS4-HMAC-SHA256"
const XAmzMetaKey = "x-amz-meta-"
const XAmzKey = "x-amz-"

// ExactMatch The form field value must match the value specified.
// This example indicates that the ACL must be set to public-read:
// {"acl": "public-read" }
type ExactMatch map[string]string

// StartWith The value must start with the specified value.
// This example indicates that the object key must start with user/user1:
// ["starts-with", "$key", "user/user1/"]
type StartWith []string

// SpecifyingRange For form fields that accept a range, separate the upper and lower limit with a comma.
// This example allows a file size from 1 to 10 MiB:
// ["content-length-range", 1048576, 10485760]
type SpecifyingRange []interface{}

type PolicyConditions struct {
	Conditions    ConditionMatching
	ConditionUsed string

	PolicyValue      string
	PolicyStartRange uint64
	PolicyStopRange  uint64
}

type ConditionMatching struct {
	ExactMatch      bool `json:"eq"`
	StartWith       bool `json:"starts-with"`
	SpecifyingRange bool `json:"content-length-range"`
}

type Policy struct {
	// The specified Amazon S3 access control list (ACL).
	Acl PolicyConditions `json:"acl" is_valid_form:"true"`

	// Specifies the acceptable bucket name.
	Bucket PolicyConditions `json:"bucket"`

	// The minimum and maximum allowable size for the uploaded content.
	ContentLengthRange PolicyConditions `json:"content_length_range"`

	// REST-specific headers. For more information,
	// see https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPOST.html.
	CacheControl       PolicyConditions `json:"Cache-Control"`
	ContentType        PolicyConditions `json:"Content-Type"`
	ContentDisposition PolicyConditions `json:"Content-Disposition"`
	ContentEncoding    PolicyConditions `json:"Content-Encoding"`
	Expires            PolicyConditions `json:"Expires"`

	// The acceptable key name or a prefix of the uploaded object.
	// This example indicates that the object key must start with user/mary:
	// ["starts-with", "$key", "user/mary/"]
	Key PolicyConditions `json:"key"`

	// The URL to which the client is redirected upon successful upload.
	SuccessActionRedirect PolicyConditions `json:"success_action_redirect"`

	// The status code returned to the client upon successful upload if success_action_redirect is not specified.
	SuccessActionStatus PolicyConditions `json:"success_action_status"`

	// The signing algorithm that must be used during signature calculation.
	// For AWS Signature Version 4, the value is AWS4-HMAC-SHA256.
	XAmzAlgorithm PolicyConditions `json:"x-amz-algorithm"`

	// The credentials that you used to calculate the signature.
	// It provides access key ID and scope information identifying region and service for which the signature is valid.
	// This should be the same scope you used in calculating the signing key for signature calculation.
	// It is a string of the following form:
	// <your-access-key-id>/<date:YYYYMMDD>/<aws-region>/<aws-service>/aws4_request
	// example := AKIAIOSFODNN7EXAMPLE/20130728/us-east-1/s3/aws4_request
	XAmzCredential PolicyConditions `json:"x-amz-credential"`

	// The date value specified in the ISO8601 formatted string.
	// For example, 20130728T000000Z.
	// The date must be same that you used in creating the signing key for signature calculation.
	XAmzDate PolicyConditions `json:"x-amz-date"`

	// Amazon DevPay security token.
	// Each request that uses Amazon DevPay requires two x-amz-security-token form fields:
	// One for the product token and one for the user token.
	// As a result, the values must be separated by commas.
	// For example, if the user token is eW91dHViZQ== and the product token is b0hnNVNKWVJIQTA=,
	// you set the POST policy entry to: { "x-amz-security-token": "eW91dHViZQ==,b0hnNVNKWVJIQTA=" }.
	XAmzSecurityToken PolicyConditions `json:"x-amz-security-token"`

	// x-amz-meta-*
	// Headers starting with this prefix are user-defined metadata.
	// Each one is stored and returned as a set of key-value pairs.
	// -Amazon S3 doesn't validate or interpret user-defined metadata-
	XAmzMeta map[string]PolicyConditions `json:"x_amz_meta"`

	// x-amz-*
	// Headers starting with this prefix are for any x-amz-* headers
	// See https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPOST.html, for more details
	XAmz map[string]PolicyConditions `json:"x_amz"`
}

func (policy Policy) Validate() error {
	return validation.ValidateStruct(&policy,
		validation.Field(&policy.Key, validation.Required),
	)
}

type AwsConfig struct {
	AwsAccessKey string // used for creating signature
	AwsRegion    string // used for creating signature
	AwsSecretKey string // used for creating signature
	AwsBucket    string
}

func (config AwsConfig) Validate() error {
	return validation.ValidateStruct(&config,
		validation.Field(&config.AwsAccessKey, validation.Required),
		validation.Field(&config.AwsRegion, validation.Required),
		validation.Field(&config.AwsSecretKey, validation.Required),
		validation.Field(&config.AwsBucket, validation.Required),
	)
}

type BaseS3Policy struct {
	AwsConfig   AwsConfig
	AwsService  string    // default "s3" for storages, used for creating signature
	Date        time.Time // used for creating signature
	ExpiredDate time.Time
	Policy      *Policy
}

func NewS3Policy(config AwsConfig) *BaseS3Policy {
	defaultPolicy := getPolicyConfig()
	if err := defaultPolicy.Validate(); err != nil {
		panic(err.Error())
	}

	base := BaseS3Policy{
		AwsConfig:  config,
		AwsService: "s3",
		Policy:     defaultPolicy,
	}

	timeNow := time.Now()
	expirationDateDefault := timeNow.Add(time.Minute * 10) // default expired 10 minutes
	base.Date = timeNow
	base.ExpiredDate = expirationDateDefault
	return &base
}

func (base *BaseS3Policy) SetExpirationDate(expirationDate time.Time) *BaseS3Policy {
	base.ExpiredDate = expirationDate
	return base
}

func (base *BaseS3Policy) setXAmzAlgorithmPolicy() *BaseS3Policy {
	base.Policy.XAmzAlgorithm.ConditionUsed = ConditionMatchingExactMatch
	base.Policy.XAmzAlgorithm.PolicyValue = AmzAlgorithm
	return base
}

func (base *BaseS3Policy) setXAmzCredentialPolicy() *BaseS3Policy {
	base.Policy.XAmzCredential.ConditionUsed = ConditionMatchingExactMatch

	accessKey := base.AwsConfig.AwsAccessKey
	credentialDate := base.Date.UTC().Format(SignatureDateFormat)
	region := base.AwsConfig.AwsRegion
	service := "s3" // default s3
	awsSignatureVersion := "aws4_request"
	policyValue := fmt.Sprintf("%s/%s/%s/%s/%s", accessKey, credentialDate, region, service, awsSignatureVersion)

	base.Policy.XAmzCredential.PolicyValue = policyValue
	return base
}

func (base *BaseS3Policy) setXAmzDatePolicy() *BaseS3Policy {
	base.Policy.XAmzDate.ConditionUsed = ConditionMatchingExactMatch
	base.Policy.XAmzDate.PolicyValue = base.Date.UTC().Format(AmzDateFormat)
	return base
}

func (base *BaseS3Policy) SetAclPolicy(conditionMatch, value string) *BaseS3Policy {
	canBeUsed := checkConditions(base.Policy.Acl.Conditions, conditionMatch)
	if !canBeUsed {
		panic("condition matching type can't be used")
	}

	base.Policy.Acl.ConditionUsed = conditionMatch
	base.Policy.Acl.PolicyValue = value
	return base
}

func (base *BaseS3Policy) SetBucketPolicy(conditionMatch, value string) *BaseS3Policy {
	canBeUsed := checkConditions(base.Policy.Bucket.Conditions, conditionMatch)
	if !canBeUsed {
		panic("condition matching type can't be used")
	}

	base.Policy.Bucket.ConditionUsed = conditionMatch
	base.Policy.Bucket.PolicyValue = value
	return base
}

func (base *BaseS3Policy) SetContentLengthPolicy(min, max uint64) *BaseS3Policy {
	base.Policy.ContentLengthRange.ConditionUsed = ConditionSpecifyingRange
	base.Policy.ContentLengthRange.PolicyStartRange = min
	base.Policy.ContentLengthRange.PolicyStopRange = max
	return base
}

func (base *BaseS3Policy) SetCacheControlPolicy(conditionMatch, value string) *BaseS3Policy {
	canBeUsed := checkConditions(base.Policy.CacheControl.Conditions, conditionMatch)
	if !canBeUsed {
		panic("condition matching type can't be used")
	}

	base.Policy.CacheControl.ConditionUsed = conditionMatch
	base.Policy.CacheControl.PolicyValue = value
	return base
}

func (base *BaseS3Policy) SetContentTypePolicy(conditionMatch, value string) *BaseS3Policy {
	canBeUsed := checkConditions(base.Policy.ContentType.Conditions, conditionMatch)
	if !canBeUsed {
		panic("condition matching type can't be used")
	}

	base.Policy.ContentType.ConditionUsed = conditionMatch
	base.Policy.ContentType.PolicyValue = value
	return base
}

func (base *BaseS3Policy) SetContentDispositionPolicy(conditionMatch, value string) *BaseS3Policy {
	canBeUsed := checkConditions(base.Policy.ContentDisposition.Conditions, conditionMatch)
	if !canBeUsed {
		panic("condition matching type can't be used")
	}

	base.Policy.ContentDisposition.ConditionUsed = conditionMatch
	base.Policy.ContentDisposition.PolicyValue = value
	return base
}

func (base *BaseS3Policy) SetContentEncodingPolicy(conditionMatch, value string) *BaseS3Policy {
	canBeUsed := checkConditions(base.Policy.ContentEncoding.Conditions, conditionMatch)
	if !canBeUsed {
		panic("condition matching type can't be used")
	}

	base.Policy.ContentEncoding.ConditionUsed = conditionMatch
	base.Policy.ContentEncoding.PolicyValue = value
	return base
}

func (base *BaseS3Policy) SetExpiresPolicy(value time.Time) *BaseS3Policy {
	canBeUsed := checkConditions(base.Policy.Expires.Conditions, ConditionMatchingExactMatch)
	if !canBeUsed {
		panic("condition matching type can't be used")
	}

	base.Policy.Expires.ConditionUsed = ConditionMatchingExactMatch
	base.Policy.Expires.PolicyValue = value.UTC().Format(ExpiredHeaderFormat)
	return base
}

func (base *BaseS3Policy) SetKeyPolicy(conditionMatch, value string) *BaseS3Policy {
	canBeUsed := checkConditions(base.Policy.Key.Conditions, conditionMatch)
	if !canBeUsed {
		panic("condition matching type can't be used")
	}

	base.Policy.Key.ConditionUsed = conditionMatch
	base.Policy.Key.PolicyValue = value
	return base
}

func (base *BaseS3Policy) SetSuccessActionRedirectPolicy(conditionMatch, value string) *BaseS3Policy {
	canBeUsed := checkConditions(base.Policy.SuccessActionRedirect.Conditions, conditionMatch)
	if !canBeUsed {
		panic("condition matching type can't be used")
	}

	base.Policy.SuccessActionRedirect.ConditionUsed = conditionMatch
	base.Policy.SuccessActionRedirect.PolicyValue = value
	return base
}

func (base *BaseS3Policy) SetSuccessActionStatusPolicy(conditionMatch, value string) *BaseS3Policy {
	canBeUsed := checkConditions(base.Policy.SuccessActionStatus.Conditions, conditionMatch)
	if !canBeUsed {
		panic("condition matching type can't be used")
	}

	base.Policy.SuccessActionStatus.ConditionUsed = conditionMatch
	base.Policy.SuccessActionStatus.PolicyValue = value
	return base
}

func (base *BaseS3Policy) SetXAmzSecurityTokenPolicy(conditionMatch, userToken, productToken string) *BaseS3Policy {
	canBeUsed := checkConditions(base.Policy.XAmzSecurityToken.Conditions, conditionMatch)
	if !canBeUsed {
		panic("condition matching type can't be used")
	}

	base.Policy.XAmzSecurityToken.ConditionUsed = conditionMatch
	base.Policy.XAmzSecurityToken.PolicyValue = fmt.Sprintf("%s,%s", userToken, productToken)
	return base
}

func (base *BaseS3Policy) SetXAmzMeta(key, conditionMatch, value string) *BaseS3Policy {
	condition := ConditionMatching{
		ExactMatch: true,
		StartWith:  true,
	}

	canBeUsed := checkConditions(condition, conditionMatch)
	if !canBeUsed {
		panic("condition matching type can't be used")
	}

	amzMeta := PolicyConditions{
		Conditions:    condition,
		ConditionUsed: conditionMatch,
		PolicyValue:   value,
	}

	xAmzMeta := base.Policy.XAmzMeta
	if xAmzMeta == nil {
		xAmzMeta = map[string]PolicyConditions{}
	}

	keyPolicy := getCustomKey(key, XAmzMetaKey)
	xAmzMeta[keyPolicy] = amzMeta

	xAmzMeta[keyPolicy] = amzMeta
	base.Policy.XAmzMeta = xAmzMeta
	return base
}

func (base *BaseS3Policy) SetXAmz(key, conditionMatch, value string) *BaseS3Policy {
	condition := ConditionMatching{
		ExactMatch: true,
	}

	canBeUsed := checkConditions(condition, conditionMatch)
	if !canBeUsed {
		panic("condition matching type can't be used")
	}

	amz := PolicyConditions{
		Conditions:    condition,
		ConditionUsed: conditionMatch,
		PolicyValue:   value,
	}

	xAmz := base.Policy.XAmz
	if xAmz == nil {
		xAmz = map[string]PolicyConditions{}
	}

	keyPolicy := getCustomKey(key, XAmzKey)
	xAmz[keyPolicy] = amz

	base.Policy.XAmz = xAmz
	return base
}

func (base *BaseS3Policy) GeneratePolicy() (policy, signature string, form Forms) {
	base.setXAmzAlgorithmPolicy()
	base.setXAmzCredentialPolicy()
	base.setXAmzDatePolicy()

	if base.Policy.Bucket.ConditionUsed == "" {
		base.SetBucketPolicy(ConditionMatchingExactMatch, base.AwsConfig.AwsBucket)
	}

	var policyData map[string]interface{}
	policyDataMarshal, _ := json.Marshal(base.Policy)
	_ = json.Unmarshal(policyDataMarshal, &policyData)

	var policyConditions []interface{}
	var formValue []FormData
	for idx, value := range policyData {
		if value == nil {
			continue
		}

		conditions, formData := getElementPolicy(idx, value.(map[string]interface{}))
		if conditions == nil {
			continue
		}

		policyConditions = append(policyConditions, conditions...)
		formValue = append(formValue, formData...)
	}

	newPolicy := map[string]interface{}{
		"expiration": base.ExpiredDate.UTC().Format(ExpirationFormat),
		"conditions": policyConditions,
	}

	newPolicyMarshal, _ := json.Marshal(newPolicy)
	encodedPolicy := base.encodePolicy(newPolicyMarshal)
	signature = base.generateSignature(encodedPolicy)

	formValue = append(formValue, FormData{
		FormName:  "policy",
		FormValue: encodedPolicy,
	})

	formValue = append(formValue, FormData{
		FormName:  "x-amz-signature",
		FormValue: signature,
	})

	forms := Forms{
		Url:      fmt.Sprintf("https://%s.%s/", base.AwsConfig.AwsBucket, "s3.amazonaws.com"),
		FormData: formValue,
	}

	return encodedPolicy, signature, forms
}

func (base *BaseS3Policy) encodePolicy(newPolicy []byte) string {
	encodedPolicy := base64.StdEncoding.EncodeToString(newPolicy)
	return encodedPolicy
}

func (base *BaseS3Policy) generateSignature(policy string) string {
	makeHmac := func(key []byte, data []byte) []byte {
		hash := hmac.New(sha256.New, key)
		hash.Write(data)
		return hash.Sum(nil)
	}

	h1 := makeHmac([]byte("AWS4"+base.AwsConfig.AwsSecretKey), []byte(base.Date.UTC().Format(SignatureDateFormat)))
	h2 := makeHmac(h1, []byte(base.AwsConfig.AwsRegion))
	h3 := makeHmac(h2, []byte(base.AwsService))
	h4 := makeHmac(h3, []byte("aws4_request"))
	signature := makeHmac(h4, []byte(policy))
	return hex.EncodeToString(signature)
}
