package s3

import "sync"

var validInputForm = map[string]bool{
	// must have in valid input form
	"key":              true,
	"bucket":           true,
	"x-amz-date":       true,
	"x-amz-credential": true,
	"x-amz-algorithm":  true,
	"policy":           true,
	"x-amz-signature":  true,

	// optional in valid input form
	"acl":                                             true,
	"Cache-Control":                                   true,
	"Content-Type":                                    true,
	"Content-Disposition":                             true,
	"Content-Encoding":                                true,
	"Expires":                                         true,
	"success_action_redirect":                         true,
	"success_action_status":                           true,
	"x-amz-storage-class":                             true,
	"x-amz-meta-":                                     true,
	"x-amz-security-token":                            true,
	"x-amz-website-redirect-location":                 true,
	"x-amz-checksum-algorithm":                        true,
	"x-amz-checksum-crc32":                            true,
	"x-amz-checksum-crc32c":                           true,
	"x-amz-checksum-sha1":                             true,
	"x-amz-checksum-sha256":                           true,
	"x-amz-server-side-encryption":                    true,
	"x-amz-server-side-encryption-aws-kms-key-id":     true,
	"x-amz-server-side-encryption-context":            true,
	"x-amz-server-side-encryption-bucket-key-enabled": true,
	"x-amz-server-side-encryption-customer-algorithm": true,
	"x-amz-server-side-encryption-customer-key":       true,
	"x-amz-server-side-encryption-customer-key-MD5":   true,
}

type PolicyConfig struct {
	PolicyData *Policy
}

var policyConfigInstance *PolicyConfig
var policyConfigOnce sync.Once

func getPolicyConfig() *Policy {
	policyConfigOnce.Do(func() {
		conditionAcl := PolicyConditions{
			Conditions: ConditionMatching{
				ExactMatch: true,
				StartWith:  true,
			},
		}

		conditionBucket := PolicyConditions{
			Conditions: ConditionMatching{
				ExactMatch: true,
				StartWith:  true,
			},
		}

		conditionContentLength := PolicyConditions{
			Conditions: ConditionMatching{
				SpecifyingRange: true,
			},
		}

		conditionCacheControl := PolicyConditions{
			Conditions: ConditionMatching{
				ExactMatch: true,
				StartWith:  true,
			},
		}

		conditionContentType := PolicyConditions{
			Conditions: ConditionMatching{
				ExactMatch: true,
				StartWith:  true,
			},
		}

		conditionContentDisposition := PolicyConditions{
			Conditions: ConditionMatching{
				ExactMatch: true,
				StartWith:  true,
			},
		}

		conditionContentEncoding := PolicyConditions{
			Conditions: ConditionMatching{
				ExactMatch: true,
				StartWith:  true,
			},
		}

		conditionExpires := PolicyConditions{
			Conditions: ConditionMatching{
				ExactMatch: true,
				StartWith:  true,
			},
		}

		conditionKey := PolicyConditions{
			Conditions: ConditionMatching{
				ExactMatch: true,
				StartWith:  true,
			},
		}

		conditionSuccessActionRedirect := PolicyConditions{
			Conditions: ConditionMatching{
				ExactMatch: true,
				StartWith:  true,
			},
		}

		conditionSuccessActionStatus := PolicyConditions{
			Conditions: ConditionMatching{
				ExactMatch: true,
			},
		}

		conditionAmzAlgo := PolicyConditions{
			Conditions: ConditionMatching{
				ExactMatch: true,
			},
		}

		conditionAmzCredential := PolicyConditions{
			Conditions: ConditionMatching{
				ExactMatch: true,
			},
		}

		conditionAmzDate := PolicyConditions{
			Conditions: ConditionMatching{
				ExactMatch: true,
			},
		}

		conditionAmzSecurityToken := PolicyConditions{
			Conditions: ConditionMatching{
				ExactMatch: true,
			},
		}

		s3Policy := Policy{
			Acl:                   conditionAcl,
			Bucket:                conditionBucket,
			ContentLengthRange:    conditionContentLength,
			CacheControl:          conditionCacheControl,
			ContentType:           conditionContentType,
			ContentDisposition:    conditionContentDisposition,
			ContentEncoding:       conditionContentEncoding,
			Expires:               conditionExpires,
			Key:                   conditionKey,
			SuccessActionRedirect: conditionSuccessActionRedirect,
			SuccessActionStatus:   conditionSuccessActionStatus,
			XAmzAlgorithm:         conditionAmzAlgo,
			XAmzCredential:        conditionAmzCredential,
			XAmzDate:              conditionAmzDate,
			XAmzSecurityToken:     conditionAmzSecurityToken,
		}

		policyConfigInstance = &PolicyConfig{
			PolicyData: &s3Policy,
		}
	})

	return policyConfigInstance.PolicyData
}
