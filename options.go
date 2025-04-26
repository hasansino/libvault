package libvault

import "log/slog"

type Option func(*Vault)

func WithLogger(l *slog.Logger) Option {
	return func(v *Vault) {
		v.logger = l
	}
}
