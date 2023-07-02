package s3Presign

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

type PolicyData interface {
	PolicyConditions | map[string]PolicyConditions | map[string]interface{}
}

func getCustomKey(key, keyPolicy string) string {
	if len(key) <= len(keyPolicy) { // check if the same length as keyPolicy (6 char)
		keyPolicy = fmt.Sprintf("%s%s", keyPolicy, key)
	} else {
		keyRune := []rune(key)
		if keyPolicy != string(keyRune[:len(keyPolicy)]) { // if the first 6 char not the same as keyPolicy, add to keyPolicy
			keyPolicy = fmt.Sprintf("%s%s", keyPolicy, key)
		} else { // if the same, use this as key policy
			keyPolicy = key
		}
	}

	return keyPolicy
}

// check if condition matching is exists and can be used by the policy
func checkConditions(policyConditions ConditionMatching, conditionMatch string) (canBeUsed bool) {
	switch conditionMatch {
	case ConditionMatchingStartWith, ConditionMatchingExactMatch, ConditionSpecifyingRange:
		var policyCondition map[string]bool
		conditionConfigMarshal, _ := json.Marshal(policyConditions)
		_ = json.Unmarshal(conditionConfigMarshal, &policyCondition)

		if _, ok := policyCondition[conditionMatch]; !ok {
			return false
		}

		return true
	default:
		panic("Conditions matching not found!")
	}
}

func conditionFunc(elementName string, policyCondition PolicyConditions) (interface{}, bool) {
	var isFormData, exists bool
	if strings.Contains(elementName, XAmzMetaKey) {
		isFormData, exists = validInputForm[XAmzMetaKey]
	} else {
		isFormData, exists = validInputForm[elementName]
	}

	if !exists {
		isFormData = false
	}

	switch policyCondition.ConditionUsed {
	case ConditionMatchingExactMatch:
		return ExactMatch{elementName: policyCondition.PolicyValue}, isFormData
	case ConditionMatchingStartWith:
		return StartWith{ConditionMatchingStartWith, fmt.Sprintf("$%s", elementName), policyCondition.PolicyValue}, isFormData
	case ConditionSpecifyingRange:
		return SpecifyingRange{ConditionSpecifyingRange, policyCondition.PolicyStartRange, policyCondition.PolicyStopRange}, isFormData
	}

	return nil, false
}

func getElementPolicy[T PolicyData](elementName string, policyData T) (conditions []interface{}, formValues []FormData) {
	switch any(policyData).(type) {
	case map[string]interface{}:
		var condition []interface{}
		var formData []FormData
		if elementName != "x_amz_meta" && elementName != "x_amz" {
			var policyConditionData PolicyConditions
			conditionMarshal, _ := json.Marshal(policyData)
			_ = json.Unmarshal(conditionMarshal, &policyConditionData)

			condition, formData = getElementPolicy(elementName, policyConditionData)
			if condition == nil {
				return nil, nil
			}
		} else {
			var policyConditionData map[string]PolicyConditions
			conditionMarshal, _ := json.Marshal(policyData)
			_ = json.Unmarshal(conditionMarshal, &policyConditionData)

			condition, formData = getElementPolicy(elementName, policyConditionData)
		}

		return condition, formData
	case PolicyConditions:
		policyConditionData := any(policyData).(PolicyConditions)
		conditionStruct, isFormData := conditionFunc(elementName, any(policyData).(PolicyConditions))
		if conditionStruct == nil {
			return nil, nil
		}

		if isFormData {
			formValues = []FormData{{FormName: elementName, FormValue: policyConditionData.PolicyValue}}
		}

		return []interface{}{conditionStruct}, formValues
	case map[string]PolicyConditions:
		policyConditionData := any(policyData).(map[string]PolicyConditions)
		for idx, value := range policyConditionData {
			conditionStruct, queryValue := getElementPolicy(idx, value)
			if conditionStruct == nil {
				continue
			}

			if queryValue != nil && len(queryValue) > 0 {
				formValues = append(formValues, queryValue...)
			}

			conditions = append(conditions, conditionStruct...)
		}

		return conditions, formValues
	default:
		return nil, nil
	}
}

func testLog(message string, data interface{}) {
	var valueData string
	switch data.(type) {
	case string:
		valueData = data.(string)
	default:
		dataMarshal, _ := json.Marshal(data)
		valueData = string(dataMarshal)
	}
	log.Printf("----------------------")
	log.Printf(message)
	log.Printf(valueData)
	log.Printf("----------------------")
}
