package reporting

import (
	"github.com/jm/security-automation-go/internal/security/classifier"
)

func ReplayInputHash(req Request) string {
	return evidenceInputHash(req)
}

func ReplayDecisionHash(comment string, cls classifier.Classification, decision string, suppressionReason string) string {
	return evidenceDecisionHash(comment, cls, decision, suppressionReason)
}
