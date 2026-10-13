package cpu

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
	"unicode/utf8"
)

// Reject duplicate object names recursively. encoding/json otherwise accepts
// duplicate names with last-value-wins semantics, which is inappropriate for a
// signed-document policy boundary. This scan never rewrites the signed bytes.
func uniqueJSON(raw []byte) error {
	if len(raw) == 0 || len(raw) > maxJSONBytes || !utf8.Valid(raw) {
		return errors.New("signed JSON size outside limit")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	budget := 100000
	var value func(int) error
	value = func(depth int) error {
		budget--
		if depth > 64 || budget < 0 {
			return errors.New("signed JSON nesting or value count outside limit")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok {
					return errors.New("non-string JSON object name")
				}
				if _, exists := seen[name]; exists {
					return fmt.Errorf("duplicate signed JSON object name %q", name)
				}
				seen[name] = struct{}{}
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		end, err := d.Token()
		if err != nil {
			return err
		}
		if (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
			return errors.New("mismatched JSON delimiter")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing signed JSON data")
	}
	return nil
}

type documentPolicyFields struct {
	IssueDate               time.Time `json:"issueDate"`
	NextUpdate              time.Time `json:"nextUpdate"`
	TCBEvaluationDataNumber uint64    `json:"tcbEvaluationDataNumber"`
}

// documentPolicy supplements upstream signature verification with independent
// rollback and freshness policy. It alone never authenticates a PCS document.
func documentPolicy(raw []byte, name string, floor uint64, now time.Time) error {
	if floor == 0 {
		return errors.New("TCB evaluation-data minimum must be nonzero")
	}
	if err := uniqueJSON(raw); err != nil {
		return err
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return err
	}
	if len(envelope) != 2 || envelope[name] == nil || envelope["signature"] == nil {
		return errors.New("unexpected Intel signed JSON envelope")
	}
	var fields documentPolicyFields
	if err := json.Unmarshal(envelope[name], &fields); err != nil {
		return err
	}
	if fields.IssueDate.IsZero() || fields.NextUpdate.IsZero() || now.Before(fields.IssueDate) || !now.Before(fields.NextUpdate) || !fields.IssueDate.Before(fields.NextUpdate) {
		return errors.New("Intel collateral is future, stale, or lacks a validity window")
	}
	if fields.TCBEvaluationDataNumber < floor {
		return errors.New("Intel collateral evaluation-data number is below independent policy")
	}
	return nil
}
