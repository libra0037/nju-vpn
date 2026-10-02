package config

import "os"

func openConfig(path string) (*os.File, error) { return os.Open(path) }
func checkIdentityDirectory(path string) error { _, err := os.Stat(path); return err }
