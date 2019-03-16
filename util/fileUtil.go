package util

import (
	"io/ioutil"
	"os"
)

type fileUtil struct{}

func (*fileUtil) Read(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}

	bytes, e := ioutil.ReadAll(f)
	if e != nil {
		_ = f.Close()
		return nil, e
	}

	return bytes, nil
}

func (*fileUtil) Exists(name string) bool {
	_, err := os.Stat(name)
	return !os.IsNotExist(err)
}
