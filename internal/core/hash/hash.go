// Copyright 2026 Keith Marshall
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hash

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cespare/xxhash/v2"
)

// GetXxHash returns a hex string of the xxhash of the data
func GetXxHash(data []byte) (string, error) {
	hasher := xxhash.New()
	_, err := hasher.Write(data)
	if err != nil {
		return "", fmt.Errorf("failed to write data to hasher: %w", err)
	}

	return strconv.FormatUint(hasher.Sum64(), 16), nil
}

// SaveContentWithHashName saves content to a file with a name based on its xxhash.
func SaveContentWithHashName(data io.Reader) (string, error) {
	temp, err := os.CreateTemp("", "capture-*.tmp")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(temp.Name()) // clean up on fail
	defer temp.Close()

	hasher := xxhash.New()

	mw := io.MultiWriter(temp, hasher) // write to file and hasher

	if _, err = io.Copy(mw, data); err != nil {
		return "", err
	}

	filename := fmt.Sprintf("%x.dat", hasher.Sum64())
	path := filepath.Join(os.TempDir(), filename)

	if err = os.Rename(temp.Name(), path); err != nil {
		return "", fmt.Errorf("failed to rename temp file: %w", err)
	}

	return path, nil
}
