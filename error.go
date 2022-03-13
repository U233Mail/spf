package spf

import "fmt"

// CheckException is an error type for mechanisms checking failures.
// If it returns an exception, mechanism processing ends and the exception value is returned.
// If it matches, processing ends and the qualifier value is returned as the result of that record.
// If it does not match, processing continues with the next mechanism.
type CheckException struct {
	result  Result
	message string
}

func NewCheckError(result Result, message string) *CheckException {
	return &CheckException{result: result, message: message}
}
func WrapCheckError(err error, result Result, message string) *CheckException {
	return &CheckException{result: result, message: fmt.Sprintf("%s: %s", message, err.Error())}
}
func (e *CheckException) Error() string {
	return fmt.Sprintf("spf(%s): %s", e.result, e.message)
}
