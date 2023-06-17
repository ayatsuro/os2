package os2

import "strconv"

type EcsError struct {
	Code int
	Msg  string
}

func (m *EcsError) Error() string {
	return strconv.Itoa(m.Code) + " " + m.Msg
}

func newError(code int, msg string) *EcsError {
	return &EcsError{
		Code: code,
		Msg:  msg,
	}
}

type DellAPIError struct {
	Code    int    `json:"code"`
	Details string `json:"details"`
}
