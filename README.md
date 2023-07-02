# aws-presignpost-s3
AWS Presign Post Policy for S3

There is many presign post policy for AWS S3 golang out there, but the one that i need is not yet available, so i created one myself.
Usually they only have bare minimum policy that can be generated. but with this package, i can add all options in [AWS S3 Post Policy](https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html).

# How To Use
you can check file [s3policy_test.go](s3policy_test.go) to see how to use it. but anyway.

1. Install the package to your project

``` go get github.com/fari-99/aws-presignpost-s3-go ```

2. Import the package to your project

```go 
import "github.com/fari-99/aws-presignpost-s3-go"
```

3. Generate policy with data you want.

> Note: 
> All data that send to when creating policy is generated or given by You. 
> We didn't check if the data is valid or not. ex: Rest API policy such as Encoding and Disposition

```go
package main
import (
	"github.com/fari-99/aws-presignpost-s3-go"
	"log"
	"time"
)

func main() {
	// this value is not real, if you want to test with the real one
	// please change all this data to your aws s3 data
	awsConfig := s3Presign.AwsConfig{
		AwsAccessKey: "AKIAIOSFODNN7EXAMPLE",
		AwsRegion:    "us-east-1",
		AwsSecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		AwsBucket:    "sigv4examplebucket",
	}

	timeExpired, _ := time.Parse(s3Presign.ExpirationFormat, "2015-12-30T12:00:00.000Z")

	s3PolicyBase := s3Presign.NewS3Policy(awsConfig)
	s3PolicyBase.SetAclPolicy(s3Presign.ConditionMatchingExactMatch, "public-read")
	s3PolicyBase.SetContentLengthPolicy(0, 10485760)
	s3PolicyBase.SetKeyPolicy(s3Presign.ConditionMatchingExactMatch, "user/user1/test.jpeg")
	s3PolicyBase.SetSuccessActionRedirectPolicy(s3Presign.ConditionMatchingExactMatch, "https://www.google.com")
	s3PolicyBase.SetSuccessActionStatusPolicy(s3Presign.ConditionMatchingStartWith, "204")
	s3PolicyBase.SetXAmzSecurityTokenPolicy(s3Presign.ConditionMatchingExactMatch, "eW91dHViZQ==", "b0hnNVNKWVJIQTA=")

	// rest api
	s3PolicyBase.SetCacheControlPolicy(s3Presign.ConditionMatchingStartWith, "no-cache")
	s3PolicyBase.SetContentTypePolicy(s3Presign.ConditionMatchingExactMatch, "image/jpeg")
	s3PolicyBase.SetContentDispositionPolicy(s3Presign.ConditionMatchingExactMatch, "Attachment; filename=test.jpeg")
	s3PolicyBase.SetContentEncodingPolicy(s3Presign.ConditionMatchingExactMatch, "token")
	s3PolicyBase.SetExpiresPolicy(timeExpired)

	// custom key
	s3PolicyBase.SetXAmzMeta("uuid", s3Presign.ConditionMatchingExactMatch, "bc2035bf-72b6-4bad-9e1f-c6c8732ac1a4")
	s3PolicyBase.SetXAmzMeta("tag", s3Presign.ConditionMatchingStartWith, "")
	// add more custom policy data

	// amazon key
	s3PolicyBase.SetXAmz("x-amz-server-side-encryption", s3Presign.ConditionMatchingExactMatch, "AES256")
	// other amazon related policy please refer to 
	// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html
	
	encodedPolicy, signature, formsData := s3PolicyBase.GeneratePolicy()
	log.Printf("Encoded Policy := \n%s", encodedPolicy)
	log.Printf("Signature := \n%s", signature)
	log.Printf("Data for your custom forms := \n%v", formsData)
	
	// if you want to generate html forms
	htmlDocumentString, err := s3Presign.GenerateFormHtml(formsData)
	if err != nil {
		panic(err.Error())
	}
	log.Printf(htmlDocumentString)
}
```