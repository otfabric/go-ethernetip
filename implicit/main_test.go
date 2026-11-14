// SPDX-License-Identifier: MIT

package implicit

import (
	"os"
	"testing"

	"github.com/otfabric/go-ethernetip/internal/testenv"
)

// TestMain fails the run when a goroutine of the module that the tests
// started is still running after them (testenv.RunLeakChecked).
func TestMain(m *testing.M) { os.Exit(testenv.RunLeakChecked(m)) }
