package main

import "os"

func openKey(path string) (*os.File, error) { return os.Open(path) }
