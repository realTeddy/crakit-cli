module example.com/demo

go 1.22

require (
	github.com/foo/bar v1.2.3
	golang.org/x/text v0.14.0
)

require github.com/baz/qux v0.1.0

require (
	github.com/indirect/dep v2.0.0+incompatible // indirect
)
