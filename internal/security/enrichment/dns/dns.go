package dns

type Result struct {
	Hostname   string
	Addresses  []string
	Confirmed  bool
	TrustedBot bool
}
