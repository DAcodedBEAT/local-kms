package config

import (
	"context"
	"log/slog"
	"os"
	"runtime/debug"
	"strings"
)

var AWSRegion string
var AWSAccountId string
var DatabasePath string

func GetEnv(ctx context.Context, key, defaultValue string) string {
	val := os.Getenv("KMS_" + key)
	if val != "" {
		return val
	}

	// Environment variables should now all be prefixed with KMS_. Support for variables without this prefix will be removed in v4.
	legacyVal := os.Getenv(key)
	if legacyVal != "" {
		slog.WarnContext(ctx, "The environment variable has been deprecated and will be removed in v4", "deprecated_key", key, "new_key", "KMS_"+key)
		return legacyVal
	}

	return defaultValue
}

func ResolveVersion(v string) string {
	if v == "" {
		return "Version Unknown"
	}
	return v
}

func ResolveGitCommit(c string) string {
	if c != "" {
		return c
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "Commit Hash Unknown"
	}

	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}

	if rev == "" {
		return "Commit Hash Unknown"
	}

	if dirty {
		return rev + "-dirty"
	}
	return rev
}

func ArnPrefix() string {
	return "arn:aws:kms:" + AWSRegion + ":" + AWSAccountId + ":"
}

func EnsureArn(prefix, target string) string {

	// If it's already an ARN
	if strings.HasPrefix(target, "arn:") {
		return target
	}

	return ArnPrefix() + prefix + target
}
