package csrf

import "time"

// getOptionsOrDefault ensures Options are non-nil and that ExpiresAt is set.
// If opts is empty or nil, a new Options is created. If ExpiresAt is zero,
// it will be set to now (UTC) + DefaultPackagedExpiry.
func getOptionsOrDefault(opts ...*Options) *Options {
	var o *Options

	if len(opts) > 0 && opts[0] != nil {
		o = opts[0]
	} else {
		o = &Options{}
	}

	if o.ExpiresAt.IsZero() {
		o.ExpiresAt = time.Now().UTC().Add(DefaultPackagedExpiry)
	}

	return o
}
