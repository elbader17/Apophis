package poc

type State struct {
	Config        ExecConfig
	Allowlist     *Allowlist
	Audit         *AuditLog
	Store         *Store
	Executor      *Executor
	AllowlistOK   bool
	AllowlistPath string
}

func NewState(cfg ExecConfig, allow *Allowlist, audit *AuditLog, store *Store) *State {
	return &State{
		Config:        cfg,
		Allowlist:     allow,
		Audit:         audit,
		Store:         store,
		Executor:      NewExecutor(cfg, audit, allow, store),
		AllowlistPath: cfg.AllowlistPath,
		AllowlistOK:   allow != nil && allow.Len() > 0,
	}
}
