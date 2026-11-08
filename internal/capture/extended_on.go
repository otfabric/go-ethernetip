// SPDX-License-Identifier: MIT

//go:build captures

package capture

// Extended is true in the extended corpus run (`make captures-extended`,
// build tag captures): the tests read the raw files of the cache instead
// of the committed excerpts.
const Extended = true
