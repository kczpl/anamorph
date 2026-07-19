set shell := ["bash", "-euo", "pipefail", "-c"]

# xcode 15+ warns about the duplicate '-lobjc' that Fyne's cgo packages
# produce; tell the Apple linker to keep quiet about it.
export CGO_LDFLAGS := if os() == "macos" { "-Wl,-no_warn_duplicate_libraries" } else { "" }

# list available recipes
default:
    @just --list

# one-time: install the fyne CLI (a dev tool, not a module dependency)
setup:
    go install fyne.io/tools/cmd/fyne@v1.7.2

# run the test suite
test:
    go test ./... -race -cover

vet:
    go vet ./...

# run the app from source
run:
    go run .

# build the macOS app bundle (anamorph.app) for this machine's architecture.
# the free ad-hoc signature seals the bundle so Gatekeeper shows its normal
# warning instead of a bogus "app is damaged" dialog on recipients' Macs.
build: vet test
    fyne package --release
    codesign --force --deep -s - anamorph.app

# install into /Applications on this machine
install: build
    rm -rf /Applications/anamorph.app
    ditto anamorph.app /Applications/anamorph.app

# zip a universal (Apple Silicon + Intel) build for sending;
# ditto preserves bundle metadata that plain zip strips.
package-mac: build
    mkdir -p dist
    CGO_ENABLED=1 GOARCH=amd64 go build -trimpath -tags release -ldflags="-w -s" -o dist/anamorph-amd64 .
    lipo -create anamorph.app/Contents/MacOS/anamorph dist/anamorph-amd64 -output dist/anamorph-universal
    mv dist/anamorph-universal anamorph.app/Contents/MacOS/anamorph
    rm dist/anamorph-amd64
    codesign --force --deep -s - anamorph.app
    ditto -c -k --sequesterRsrc --keepParent anamorph.app dist/anamorph-macos.zip
