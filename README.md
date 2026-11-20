# ipvs - networking for containers

![Test](https://github.com/moby/ipvs/workflows/Test/badge.svg)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/moby/ipvs)](https://pkg.go.dev/github.com/moby/ipvs)
[![GitHub License](https://img.shields.io/github/license/moby/ipvs)](LICENSE)

ipvs provides a native Go implementation for communicating with IPVS kernel module using a netlink socket.


#### Using ipvs

```go
import (
	"log"

	"github.com/moby/ipvs"
)

func main() {
	handle, err := ipvs.New("")
	if err != nil {
		log.Fatalf("ipvs.New: %s", err)
	}
	svcs, err := handle.GetServices()
	if err != nil {
		log.Fatalf("handle.GetServices: %s", err)
	}
}
```

#### Partial results

A single malformed record in a netlink dump response makes `GetServices` and
`GetDestinations` fail. To keep the remaining state, use the partial variants,
which return every valid record in response order and report each invalid one
by its index:

```go
svcs, err := handle.GetServicesPartial()

var partial *ipvs.PartialResultError
if errors.As(err, &partial) {
	for _, record := range partial.Records {
		log.Printf("skipping service record %d: %v", record.Index, record.Err)
	}
}
```

The per-record errors match `ipvs.ErrTruncatedRecord`,
`ipvs.ErrMissingAttribute`, `ipvs.ErrMalformedRecord`, or
`ipvs.ErrUnknownAddressFamily` with `errors.Is`.

## Contributing

Want to hack on ipvs? [Docker's contributions guidelines](https://github.com/docker/docker/blob/master/CONTRIBUTING.md) apply.

## Copyright and license

Copyright 2015 Docker, inc. Code released under the [Apache 2.0 license](LICENSE).
