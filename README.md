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
	awsConfig := s3.AwsConfig{
		AwsAccessKey: "AKIAIOSFODNN7EXAMPLE",
		AwsRegion:    "us-east-1",
		AwsSecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		AwsBucket:    "sigv4examplebucket",
	}

	timeExpired, _ := time.Parse(s3.ExpirationFormat, "2015-12-30T12:00:00.000Z")

	s3PolicyBase := s3.NewS3Policy(awsConfig)
	s3PolicyBase.SetAclPolicy(s3.ConditionMatchingExactMatch, "public-read")
	s3PolicyBase.SetContentLengthPolicy(0, 10485760)
	s3PolicyBase.SetKeyPolicy(s3.ConditionMatchingExactMatch, "user/user1/test.jpeg")
	s3PolicyBase.SetSuccessActionRedirectPolicy(s3.ConditionMatchingExactMatch, "https://www.google.com")
	s3PolicyBase.SetSuccessActionStatusPolicy(s3.ConditionMatchingStartWith, "204")
	s3PolicyBase.SetXAmzSecurityTokenPolicy(s3.ConditionMatchingExactMatch, "eW91dHViZQ==", "b0hnNVNKWVJIQTA=")

	// rest api
	s3PolicyBase.SetCacheControlPolicy(s3.ConditionMatchingStartWith, "no-cache")
	s3PolicyBase.SetContentTypePolicy(s3.ConditionMatchingExactMatch, "image/jpeg")
	s3PolicyBase.SetContentDispositionPolicy(s3.ConditionMatchingExactMatch, "Attachment; filename=test.jpeg")
	s3PolicyBase.SetContentEncodingPolicy(s3.ConditionMatchingExactMatch, "token")
	s3PolicyBase.SetExpiresPolicy(timeExpired)

	// custom key
	s3PolicyBase.SetXAmzMeta("uuid", s3.ConditionMatchingExactMatch, "bc2035bf-72b6-4bad-9e1f-c6c8732ac1a4")
	s3PolicyBase.SetXAmzMeta("tag", s3.ConditionMatchingStartWith, "")
	// add more custom policy data

	// amazon key
	s3PolicyBase.SetXAmz("x-amz-server-side-encryption", s3.ConditionMatchingExactMatch, "AES256")
	// other amazon related policy please refer to 
	// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html
	
	encodedPolicy, signature, formsData := s3PolicyBase.GeneratePolicy()
	log.Printf("Encoded Policy := \n%s", encodedPolicy)
	log.Printf("Signature := \n%s", signature)
	log.Printf("Data for your custom forms := \n%v", formsData)
	
	// if you want to generate html forms
	htmlDocumentString, err := s3.GenerateFormHtml(formsData)
	if err != nil {
		panic(err.Error())
	}
	log.Printf(htmlDocumentString)
}
```