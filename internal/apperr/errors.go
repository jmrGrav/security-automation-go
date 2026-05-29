package apperr

import (
	"errors"
	"fmt"
)

type Error struct {
	Op  string
	Msg string
	Err error
}

func (e *Error) Error() string {
	switch {
	case e == nil:
		return "<nil>"
	case e.Op != "" && e.Msg != "" && e.Err != nil:
		return fmt.Sprintf("%s: %s: %v", e.Op, e.Msg, e.Err)
	case e.Op != "" && e.Err != nil:
		return fmt.Sprintf("%s: %v", e.Op, e.Err)
	case e.Msg != "" && e.Err != nil:
		return fmt.Sprintf("%s: %v", e.Msg, e.Err)
	case e.Op != "" && e.Msg != "":
		return fmt.Sprintf("%s: %s", e.Op, e.Msg)
	case e.Op != "":
		return e.Op
	case e.Msg != "":
		return e.Msg
	default:
		return e.Err.Error()
	}
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func Wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	return &Error{Op: op, Err: err}
}

func Wrapf(op string, err error, format string, args ...any) error {
	if err == nil {
		return nil
	}
	return &Error{
		Op:  op,
		Msg: fmt.Sprintf(format, args...),
		Err: err,
	}
}

func New(op, msg string) error {
	return &Error{Op: op, Msg: msg}
}

func Newf(op, format string, args ...any) error {
	return &Error{Op: op, Msg: fmt.Sprintf(format, args...)}
}

func Is(err, target error) bool {
	return errors.Is(err, target)
}
