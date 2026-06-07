package detect

func DetectCrowdSec(cfg Config) Result {
	return Result{Name: "crowdsec", Details: map[string]string{}}
}

func DetectOpenResty(cfg Config) Result {
	return Result{Name: "openresty", Details: map[string]string{}}
}

func DetectNginx(cfg Config) Result {
	return Result{Name: "nginx", Details: map[string]string{}}
}

func DetectCloudflareConfig(cfg Config) Result {
	return Result{Name: "cloudflare", Details: map[string]string{}}
}

func DetectSQLite(cfg Config) Result {
	return Result{Name: "sqlite", Details: map[string]string{}}
}

func DetectSystemd(cfg Config) Result {
	return Result{Name: "systemd", Details: map[string]string{}}
}

func DetectStateDir(cfg Config) Result {
	return Result{Name: "state-directory", Details: map[string]string{}}
}

func DetectLogDir(cfg Config) Result {
	return Result{Name: "log-directory", Details: map[string]string{}}
}

func DetectSecretDir(cfg Config) Result {
	return Result{Name: "secret-directory", Details: map[string]string{}}
}
