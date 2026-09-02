// The Onserva agent has NO third-party dependencies, by design.
//
// It is installed on machines we do not own, sometimes for clients who will
// want to satisfy themselves about what it does. Every line of it is either
// standard library or in this repository, so `go mod verify` has nothing to
// verify, there is no supply chain to compromise, and the whole thing can be
// read in an afternoon.
//
// It reads Linux's own /proc filesystem directly rather than using a metrics
// library, for the same reason.
module github.com/Onserva/onserva-agent

go 1.24
