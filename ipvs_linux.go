package ipvs

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	netlinkRecvSocketsTimeout = 3 * time.Second
	netlinkSendSocketTimeout  = 30 * time.Second
)

// Service defines an IPVS service in its entirety.
type Service struct {
	// Virtual service address.
	Address  net.IP
	Protocol uint16
	Port     uint16
	FWMark   uint32 // Firewall mark of the service.

	// Virtual service options.
	SchedName     string
	Flags         uint32
	Timeout       uint32
	Netmask       uint32
	AddressFamily uint16
	PEName        string
	Stats         SvcStats
}

// SvcStats defines an IPVS service statistics
type SvcStats struct {
	Connections uint32
	PacketsIn   uint32
	PacketsOut  uint32
	BytesIn     uint64
	BytesOut    uint64
	CPS         uint32
	BPSOut      uint32
	PPSIn       uint32
	PPSOut      uint32
	BPSIn       uint32
}

// Destination defines an IPVS destination (real server) in its
// entirety.
type Destination struct {
	Address               net.IP
	Port                  uint16
	Weight                int
	ConnectionFlags       uint32
	AddressFamily         uint16
	UpperThreshold        uint32
	LowerThreshold        uint32
	ActiveConnections     int
	InactiveConnections   int
	PersistentConnections int
	Stats                 DstStats
}

// DstStats defines IPVS destination (real server) statistics
type DstStats SvcStats

// Config defines IPVS timeout configuration
type Config struct {
	TimeoutTCP    time.Duration
	TimeoutTCPFin time.Duration
	TimeoutUDP    time.Duration
}

// Errors identifying why a record from a netlink dump response could not be
// decoded. They are wrapped by the per-record errors reported through
// [PartialResultError], so callers can use [errors.Is] to classify failures.
var (
	// ErrMalformedRecord indicates that a record (or one of its attributes)
	// could not be parsed.
	ErrMalformedRecord = errors.New("ipvs: malformed netlink record")
	// ErrTruncatedRecord indicates that a record was shorter than required
	// by the netlink protocol, or that an attribute claimed more data than
	// was available.
	ErrTruncatedRecord = errors.New("ipvs: truncated netlink record")
	// ErrMissingAttribute indicates that a record did not contain a required
	// attribute, and decoding it would have produced a misleading zero value.
	ErrMissingAttribute = errors.New("ipvs: missing required netlink attribute")
	// ErrUnknownAddressFamily indicates that a record carried an address
	// family that is not supported.
	ErrUnknownAddressFamily = errors.New("ipvs: unknown address family")
)

// RecordError identifies one record in a netlink dump response that could not
// be decoded.
type RecordError struct {
	// Index is the zero-based position of the record in the netlink response.
	// Records are numbered in the order returned by the kernel, including
	// records that were decoded successfully.
	Index int
	// Err describes why the record could not be decoded. It wraps one of
	// ErrMalformedRecord, ErrTruncatedRecord, ErrMissingAttribute, or
	// ErrUnknownAddressFamily.
	Err error
}

// Error implements the error interface.
func (e *RecordError) Error() string {
	return fmt.Sprintf("netlink record %d: %v", e.Index, e.Err)
}

// Unwrap returns the underlying decoding error.
func (e *RecordError) Unwrap() error {
	return e.Err
}

// PartialResultError is returned by the partial query methods when a netlink
// dump response contained records that could not be decoded. The records that
// were decoded successfully are returned together with this error, in netlink
// response order; the invalid records are reported individually in Records.
type PartialResultError struct {
	// Resource names the kind of record that was requested, for example
	// "service" or "destination".
	Resource string
	// Total is the number of records in the netlink response, including the
	// ones that could not be decoded.
	Total int
	// Records lists every record that could not be decoded, ordered by Index.
	Records []*RecordError
}

// Error implements the error interface.
func (e *PartialResultError) Error() string {
	if len(e.Records) == 0 {
		return fmt.Sprintf("ipvs: %s records could not be decoded", e.Resource)
	}
	return fmt.Sprintf("ipvs: %d of %d %s records could not be decoded: %v",
		len(e.Records), e.Total, e.Resource, e.Records[0])
}

// Unwrap returns the per-record errors, allowing errors.Is and errors.As to
// classify individual decoding failures.
func (e *PartialResultError) Unwrap() []error {
	errs := make([]error, 0, len(e.Records))
	for _, record := range e.Records {
		errs = append(errs, record)
	}
	return errs
}

// Handle provides a namespace specific ipvs handle to program ipvs
// rules.
type Handle struct {
	// mu serializes access to sock. A netlink socket carries a single
	// sequence of requests and replies, so concurrent queries on the same
	// handle must not interleave their send/receive cycles.
	mu   sync.Mutex
	seq  uint32
	sock *nl.NetlinkSocket

	// executeFn overrides how requests are sent when non-nil. It is set by
	// tests to supply synthetic netlink responses without touching the
	// kernel; production handles leave it nil.
	executeFn func(*nl.NetlinkRequest) ([][]byte, error)
}

// New provides a new ipvs handle in the namespace pointed to by the
// passed path. It will return a valid handle or an error in case an
// error occurred while creating the handle.
func New(path string) (*Handle, error) {
	if _, err := ipvsFamily(); err != nil {
		return nil, err
	}

	n := netns.None()
	if path != "" {
		var err error
		n, err = netns.GetFromPath(path)
		if err != nil {
			return nil, err
		}
		defer func() { _ = n.Close() }()
	}

	sock, err := nl.GetNetlinkSocketAt(n, netns.None(), unix.NETLINK_GENERIC)
	if err != nil {
		return nil, err
	}
	// Add operation timeout to avoid deadlocks
	tv := unix.NsecToTimeval(netlinkSendSocketTimeout.Nanoseconds())
	if err := sock.SetSendTimeout(&tv); err != nil {
		return nil, err
	}
	tv = unix.NsecToTimeval(netlinkRecvSocketsTimeout.Nanoseconds())
	if err := sock.SetReceiveTimeout(&tv); err != nil {
		return nil, err
	}

	return &Handle{sock: sock}, nil
}

// Close closes the ipvs handle. The handle is invalid after Close
// returns.
func (i *Handle) Close() {
	if i.sock != nil {
		i.sock.Close()
	}
}

// NewService creates a new ipvs service in the passed handle.
func (i *Handle) NewService(s *Service) error {
	return i.doCmd(s, nil, ipvsCmdNewService)
}

// IsServicePresent queries for the ipvs service in the passed handle.
func (i *Handle) IsServicePresent(s *Service) bool {
	return nil == i.doCmd(s, nil, ipvsCmdGetService)
}

// UpdateService updates an already existing service in the passed
// handle.
func (i *Handle) UpdateService(s *Service) error {
	return i.doCmd(s, nil, ipvsCmdSetService)
}

// DelService deletes an already existing service in the passed
// handle.
func (i *Handle) DelService(s *Service) error {
	return i.doCmd(s, nil, ipvsCmdDelService)
}

// Flush deletes all existing services in the passed
// handle.
func (i *Handle) Flush() error {
	_, err := i.doCmdWithoutAttr(ipvsCmdFlush)
	return err
}

// NewDestination creates a new real server in the passed ipvs
// service which should already be existing in the passed handle.
func (i *Handle) NewDestination(s *Service, d *Destination) error {
	return i.doCmd(s, d, ipvsCmdNewDest)
}

// UpdateDestination updates an already existing real server in the
// passed ipvs service in the passed handle.
func (i *Handle) UpdateDestination(s *Service, d *Destination) error {
	return i.doCmd(s, d, ipvsCmdSetDest)
}

// DelDestination deletes an already existing real server in the
// passed ipvs service in the passed handle.
func (i *Handle) DelDestination(s *Service, d *Destination) error {
	return i.doCmd(s, d, ipvsCmdDelDest)
}

// GetServices returns an array of services configured on the Node.
//
// If one or more records in the netlink response cannot be decoded, GetServices
// fails without returning any of the services; use [Handle.GetServicesPartial]
// to retrieve the valid records together with a description of the invalid
// ones.
func (i *Handle) GetServices() ([]*Service, error) {
	return i.doGetServicesCmd(nil)
}

// GetServicesPartial returns the services configured on the Node that could be
// decoded, and reports records that could not be decoded as a
// [*PartialResultError]. The returned services preserve the order of the
// netlink response; record indexes in the error refer to positions in that
// response.
//
// A nil error is returned when every record was decoded. Errors unrelated to
// decoding (for example failures to query the kernel) are returned as-is and
// no services are returned.
func (i *Handle) GetServicesPartial() ([]*Service, error) {
	return i.doGetServicesPartialCmd(nil)
}

// GetDestinations returns an array of Destinations configured for this Service.
//
// If one or more records in the netlink response cannot be decoded,
// GetDestinations fails without returning any of the destinations; use
// [Handle.GetDestinationsPartial] to retrieve the valid records together with a
// description of the invalid ones.
func (i *Handle) GetDestinations(s *Service) ([]*Destination, error) {
	return i.doGetDestinationsCmd(s, nil)
}

// GetDestinationsPartial returns the destinations configured for this Service
// that could be decoded, and reports records that could not be decoded as a
// [*PartialResultError]. The returned destinations preserve the order of the
// netlink response; record indexes in the error refer to positions in that
// response.
//
// A nil error is returned when every record was decoded. Errors unrelated to
// decoding (for example failures to query the kernel) are returned as-is and
// no destinations are returned.
func (i *Handle) GetDestinationsPartial(s *Service) ([]*Destination, error) {
	return i.doGetDestinationsPartialCmd(s, nil)
}

// GetService gets details of a specific IPVS services, useful in updating statisics etc.,
func (i *Handle) GetService(s *Service) (*Service, error) {
	res, err := i.doGetServicesCmd(s)
	if err != nil {
		return nil, err
	}

	// We are looking for exactly one service otherwise error out
	if len(res) != 1 {
		return nil, fmt.Errorf("expected only one service obtained=%d", len(res))
	}

	return res[0], nil
}

// GetConfig returns the current timeout configuration
func (i *Handle) GetConfig() (*Config, error) {
	return i.doGetConfigCmd()
}

// SetConfig set the current timeout configuration. 0: no change
func (i *Handle) SetConfig(c *Config) error {
	return i.doSetConfigCmd(c)
}
