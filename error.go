package spf

import "fmt"

// CheckError is an error type for mechanisms checking failures.
// If it returns an exception, mechanism processing ends and the exception value is returned.
// If it matches, processing ends and the qualifier value is returned as the result of that record.
// If it does not match, processing continues with the next mechanism.
type CheckError struct {
	result   Result
	message  string
	internal error
}

func NewCheckError(result Result, message string) *CheckError {
	return &CheckError{result: result, message: message}
}
func WrapCheckError(err error, result Result, message string) *CheckError {
	return &CheckError{result: result, message: message, internal: err}
}
func (e *CheckError) Error() string {
	if e.internal == nil {
		return fmt.Sprintf("spf(%s): %s", e.result, e.message)
	} else {
		return fmt.Sprintf("spf(%s): %s: %s", e.result, e.message, e.internal.Error())
	}
}

func (e *CheckError) Unwrap() error {
	return e.internal
}
