package ipvs

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// serviceRecord builds the raw payload of one netlink dump message, i.e. a
// generic-netlink header followed by an IPVS_CMD_ATTR_SERVICE attribute
// containing the given service attributes. Passing nil attrs produces a record
// with an empty service attribute.
func serviceRecord(t *testing.T, attrs ...nl.NetlinkRequestData) []byte {
	t.Helper()
	return recordPayload(t, ipvsCmdAttrService, attrs...)
}

// destinationRecord builds the raw payload of one destination dump message.
func destinationRecord(t *testing.T, attrs ...nl.NetlinkRequestData) []byte {
	t.Helper()
	return recordPayload(t, ipvsCmdAttrDest, attrs...)
}

func recordPayload(t *testing.T, parent ipvsCmdAttr, attrs ...nl.NetlinkRequestData) []byte {
	t.Helper()
	nested := nl.NewRtAttr(int(parent), nil)
	for _, attr := range attrs {
		serialized := attr.Serialize()
		nested.Data = append(nested.Data, serialized...)
	}
	return append((&genlMsgHdr{cmd: uint8(ipvsCmdGetService), version: 1}).Serialize(), nested.Serialize()...)
}

// uint16Attr, ipAttr, and stringAttr build IPVS attributes that carry the
// given value.
func uint16Attr(attrType ipvsSvcAttr, v uint16) nl.NetlinkRequestData {
	return nl.NewRtAttr(int(attrType), nl.Uint16Attr(v))
}

func ipAttr(attrType ipvsSvcAttr, ip []byte) nl.NetlinkRequestData {
	return nl.NewRtAttr(int(attrType), ip)
}

func stringAttr(attrType ipvsSvcAttr, s string) nl.NetlinkRequestData {
	return nl.NewRtAttr(int(attrType), nl.ZeroTerminated(s))
}

// validServiceRecord builds a complete IPv4 service record.
func validServiceRecord(t *testing.T, lastOctet byte) []byte {
	t.Helper()
	return serviceRecord(t,
		uint16Attr(ipvsSvcAttrAddressFamily, unix.AF_INET),
		uint16Attr(ipvsSvcAttrProtocol, unix.IPPROTO_TCP),
		ipAttr(ipvsSvcAttrAddress, []byte{192, 0, 2, lastOctet}),
		nl.NewRtAttr(int(ipvsSvcAttrPort), []byte{0x00, 0x50}),
		stringAttr(ipvsSvcAttrSchedName, "rr"),
	)
}

// validDestinationRecord builds a complete IPv4 destination record.
func validDestinationRecord(t *testing.T, lastOctet byte) []byte {
	t.Helper()
	return destinationRecord(t,
		nl.NewRtAttr(int(ipvsDestAttrAddressFamily), nl.Uint16Attr(unix.AF_INET)),
		nl.NewRtAttr(int(ipvsDestAttrAddress), []byte{10, 0, 0, lastOctet}),
		nl.NewRtAttr(int(ipvsDestAttrPort), []byte{0x13, 0x88}),
		nl.NewRtAttr(int(ipvsDestAttrWeight), nl.Uint32Attr(1)),
	)
}

// fakeHandle returns a handle whose queries are answered with the given
// payloads instead of a netlink socket.
func fakeHandle(payloads ...[]byte) *Handle {
	return &Handle{
		executeFn: func(*nl.NetlinkRequest) ([][]byte, error) {
			return payloads, nil
		},
	}
}

func TestGetServicesPartialMixedRecords(t *testing.T) {
	payloads := [][]byte{
		validServiceRecord(t, 1),
		nil, // too short to contain a generic netlink header
		validServiceRecord(t, 2),
		// A record whose service attribute contains a truncated address
		// family value (two-byte field cut to one byte).
		serviceRecord(t, nl.NewRtAttr(int(ipvsSvcAttrAddressFamily), []byte{unix.AF_INET})),
		validServiceRecord(t, 3),
	}

	services, err := fakeHandle(payloads...).GetServicesPartial()

	var partial *PartialResultError
	if !errors.As(err, &partial) {
		t.Fatalf("GetServicesPartial() error = %v, want *PartialResultError", err)
	}
	if partial.Resource != "service" {
		t.Errorf("Resource = %q, want %q", partial.Resource, "service")
	}
	if partial.Total != len(payloads) {
		t.Errorf("Total = %d, want %d", partial.Total, len(payloads))
	}
	if len(partial.Records) != 2 {
		t.Fatalf("len(Records) = %d, want 2", len(partial.Records))
	}
	if got, want := partial.Records[0].Index, 1; got != want {
		t.Errorf("Records[0].Index = %d, want %d", got, want)
	}
	if !errors.Is(partial.Records[0].Err, ErrTruncatedRecord) {
		t.Errorf("Records[0].Err = %v, want ErrTruncatedRecord", partial.Records[0].Err)
	}
	if got, want := partial.Records[1].Index, 3; got != want {
		t.Errorf("Records[1].Index = %d, want %d", got, want)
	}
	if !errors.Is(partial.Records[1].Err, ErrTruncatedRecord) {
		t.Errorf("Records[1].Err = %v, want ErrTruncatedRecord", partial.Records[1].Err)
	}

	// Valid records are preserved, in netlink response order.
	var got []string
	for _, svc := range services {
		got = append(got, svc.Address.String())
	}
	want := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("services = %v, want %v", got, want)
	}

	// The errors.Is classification works through the aggregate error too.
	if !errors.Is(err, ErrTruncatedRecord) {
		t.Errorf("errors.Is(err, ErrTruncatedRecord) = false, want true")
	}
}

func TestGetServicesPartialAllValid(t *testing.T) {
	services, err := fakeHandle(
		validServiceRecord(t, 1),
		validServiceRecord(t, 2),
	).GetServicesPartial()
	if err != nil {
		t.Fatalf("GetServicesPartial() error = %v, want nil", err)
	}
	if len(services) != 2 {
		t.Fatalf("len(services) = %d, want 2", len(services))
	}
}

func TestGetServicesPartialAllInvalid(t *testing.T) {
	services, err := fakeHandle(nil, []byte{1, 2, 3}).GetServicesPartial()

	var partial *PartialResultError
	if !errors.As(err, &partial) {
		t.Fatalf("GetServicesPartial() error = %v, want *PartialResultError", err)
	}
	if len(partial.Records) != 2 || partial.Total != 2 {
		t.Errorf("got %d/%d invalid records, want 2/2", len(partial.Records), partial.Total)
	}
	if len(services) != 0 {
		t.Errorf("len(services) = %d, want 0", len(services))
	}
}

func TestGetDestinationsPartialMixedRecords(t *testing.T) {
	payloads := [][]byte{
		validDestinationRecord(t, 2),
		// Unknown address family.
		destinationRecord(t, nl.NewRtAttr(int(ipvsDestAttrAddressFamily), nl.Uint16Attr(0x7fff)),
			nl.NewRtAttr(int(ipvsDestAttrAddress), []byte{10, 0, 0, 1})),
		validDestinationRecord(t, 3),
		// Missing address attribute entirely.
		destinationRecord(t, nl.NewRtAttr(int(ipvsDestAttrAddressFamily), nl.Uint16Attr(unix.AF_INET))),
	}

	dests, err := fakeHandle(payloads...).GetDestinationsPartial(&Service{})

	var partial *PartialResultError
	if !errors.As(err, &partial) {
		t.Fatalf("GetDestinationsPartial() error = %v, want *PartialResultError", err)
	}
	if partial.Resource != "destination" {
		t.Errorf("Resource = %q, want %q", partial.Resource, "destination")
	}
	if len(partial.Records) != 2 {
		t.Fatalf("len(Records) = %d, want 2", len(partial.Records))
	}
	if got, want := partial.Records[0].Index, 1; got != want {
		t.Errorf("Records[0].Index = %d, want %d", got, want)
	}
	if !errors.Is(partial.Records[0].Err, ErrUnknownAddressFamily) {
		t.Errorf("Records[0].Err = %v, want ErrUnknownAddressFamily", partial.Records[0].Err)
	}
	if got, want := partial.Records[1].Index, 3; got != want {
		t.Errorf("Records[1].Index = %d, want %d", got, want)
	}
	if !errors.Is(partial.Records[1].Err, ErrMissingAttribute) {
		t.Errorf("Records[1].Err = %v, want ErrMissingAttribute", partial.Records[1].Err)
	}

	if len(dests) != 2 {
		t.Fatalf("len(dests) = %d, want 2", len(dests))
	}
	if got, want := dests[0].Address.String(), "10.0.0.2"; got != want {
		t.Errorf("dests[0].Address = %q, want %q", got, want)
	}
	if got, want := dests[1].Address.String(), "10.0.0.3"; got != want {
		t.Errorf("dests[1].Address = %q, want %q", got, want)
	}
}

// TestStrictQueriesStayStrict verifies that GetServices/GetDestinations keep
// their all-or-nothing contract, now reporting the failing record's position.
func TestStrictQueriesStayStrict(t *testing.T) {
	t.Run("services", func(t *testing.T) {
		h := fakeHandle(validServiceRecord(t, 1), nil, validServiceRecord(t, 2))
		services, err := h.GetServices()
		if err == nil {
			t.Fatal("GetServices() error = nil, want error")
		}
		if services != nil {
			t.Errorf("GetServices() returned %d services alongside error, want none", len(services))
		}
		if !errors.Is(err, ErrTruncatedRecord) {
			t.Errorf("GetServices() error = %v, want ErrTruncatedRecord", err)
		}
		if want := "parse service record 1"; !strings.Contains(err.Error(), want) {
			t.Errorf("GetServices() error = %q, want it to contain %q", err, want)
		}
		// Also check through the strict single-record API.
		if _, err := h.GetService(&Service{}); err == nil {
			t.Error("GetService() error = nil, want error")
		}
	})

	t.Run("destinations", func(t *testing.T) {
		h := fakeHandle(validDestinationRecord(t, 2), nil)
		dests, err := h.GetDestinations(&Service{})
		if err == nil {
			t.Fatal("GetDestinations() error = nil, want error")
		}
		// GetDestinations has historically returned the records decoded
		// before the failing one.
		if len(dests) != 1 {
			t.Errorf("GetDestinations() returned %d destinations alongside error, want 1", len(dests))
		}
		if !errors.Is(err, ErrTruncatedRecord) {
			t.Errorf("GetDestinations() error = %v, want ErrTruncatedRecord", err)
		}
		if want := "parse destination record 1"; !strings.Contains(err.Error(), want) {
			t.Errorf("GetDestinations() error = %q, want it to contain %q", err, want)
		}
	})
}

func TestAssembleServiceRejectsIncompleteRecords(t *testing.T) {
	tests := []struct {
		name    string
		attrs   []syscall.NetlinkRouteAttr
		wantErr error
	}{
		{
			name:    "no attributes",
			attrs:   nil,
			wantErr: ErrMissingAttribute,
		},
		{
			name: "no address family",
			attrs: []syscall.NetlinkRouteAttr{
				{Attr: syscall.RtAttr{Type: uint16(ipvsSvcAttrAddress)}, Value: []byte{192, 0, 2, 1}},
			},
			wantErr: ErrMissingAttribute,
		},
		{
			name: "unknown address family",
			attrs: []syscall.NetlinkRouteAttr{
				{Attr: syscall.RtAttr{Type: uint16(ipvsSvcAttrAddressFamily)}, Value: nl.Uint16Attr(0xbeef)},
				{Attr: syscall.RtAttr{Type: uint16(ipvsSvcAttrAddress)}, Value: []byte{192, 0, 2, 1}},
			},
			wantErr: ErrUnknownAddressFamily,
		},
		{
			name: "neither address nor fwmark",
			attrs: []syscall.NetlinkRouteAttr{
				{Attr: syscall.RtAttr{Type: uint16(ipvsSvcAttrAddressFamily)}, Value: nl.Uint16Attr(unix.AF_INET)},
				{Attr: syscall.RtAttr{Type: uint16(ipvsSvcAttrProtocol)}, Value: nl.Uint16Attr(unix.IPPROTO_TCP)},
			},
			wantErr: ErrMissingAttribute,
		},
		{
			name: "truncated address family",
			attrs: []syscall.NetlinkRouteAttr{
				{Attr: syscall.RtAttr{Type: uint16(ipvsSvcAttrAddressFamily)}, Value: []byte{unix.AF_INET}},
			},
			wantErr: ErrTruncatedRecord,
		},
		{
			name: "truncated address for IPv4",
			attrs: []syscall.NetlinkRouteAttr{
				{Attr: syscall.RtAttr{Type: uint16(ipvsSvcAttrAddressFamily)}, Value: nl.Uint16Attr(unix.AF_INET)},
				{Attr: syscall.RtAttr{Type: uint16(ipvsSvcAttrAddress)}, Value: []byte{192, 0}},
			},
			wantErr: ErrTruncatedRecord,
		},
		{
			name: "truncated port",
			attrs: []syscall.NetlinkRouteAttr{
				{Attr: syscall.RtAttr{Type: uint16(ipvsSvcAttrAddressFamily)}, Value: nl.Uint16Attr(unix.AF_INET)},
				{Attr: syscall.RtAttr{Type: uint16(ipvsSvcAttrAddress)}, Value: []byte{192, 0, 2, 1}},
				{Attr: syscall.RtAttr{Type: uint16(ipvsSvcAttrPort)}, Value: []byte{0x00}},
			},
			wantErr: ErrTruncatedRecord,
		},
		{
			name: "truncated stats",
			attrs: []syscall.NetlinkRouteAttr{
				{Attr: syscall.RtAttr{Type: uint16(ipvsSvcAttrAddressFamily)}, Value: nl.Uint16Attr(unix.AF_INET)},
				{Attr: syscall.RtAttr{Type: uint16(ipvsSvcAttrAddress)}, Value: []byte{192, 0, 2, 1}},
				{Attr: syscall.RtAttr{Type: uint16(ipvsSvcAttrStats)}, Value: []byte{4, 0, 1, 0}},
			},
			wantErr: ErrTruncatedRecord,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := assembleService(tc.attrs)
			if err == nil {
				t.Fatalf("assembleService() = %+v, want error", got)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("assembleService() error = %v, want %v", err, tc.wantErr)
			}
		})
	}

	t.Run("firewall-mark service without address", func(t *testing.T) {
		got, err := assembleService([]syscall.NetlinkRouteAttr{
			{Attr: syscall.RtAttr{Type: uint16(ipvsSvcAttrAddressFamily)}, Value: nl.Uint16Attr(unix.AF_INET)},
			{Attr: syscall.RtAttr{Type: uint16(ipvsSvcAttrFWMark)}, Value: nl.Uint32Attr(1234)},
		})
		if err != nil {
			t.Fatalf("assembleService() error = %v, want nil", err)
		}
		if got.FWMark != 1234 {
			t.Errorf("FWMark = %d, want 1234", got.FWMark)
		}
	})
}

func TestAssembleDestinationRejectsIncompleteRecords(t *testing.T) {
	tests := []struct {
		name    string
		attrs   []syscall.NetlinkRouteAttr
		wantErr error
	}{
		{
			name:    "no attributes",
			attrs:   nil,
			wantErr: ErrMissingAttribute,
		},
		{
			name: "missing address",
			attrs: []syscall.NetlinkRouteAttr{
				{Attr: syscall.RtAttr{Type: uint16(ipvsDestAttrAddressFamily)}, Value: nl.Uint16Attr(unix.AF_INET)},
			},
			wantErr: ErrMissingAttribute,
		},
		{
			name: "unknown address family",
			attrs: []syscall.NetlinkRouteAttr{
				{Attr: syscall.RtAttr{Type: uint16(ipvsDestAttrAddressFamily)}, Value: nl.Uint16Attr(0xbeef)},
				{Attr: syscall.RtAttr{Type: uint16(ipvsDestAttrAddress)}, Value: []byte{10, 0, 0, 1}},
			},
			wantErr: ErrUnknownAddressFamily,
		},
		{
			name: "truncated weight",
			attrs: []syscall.NetlinkRouteAttr{
				{Attr: syscall.RtAttr{Type: uint16(ipvsDestAttrAddress)}, Value: []byte{10, 0, 0, 1}},
				{Attr: syscall.RtAttr{Type: uint16(ipvsDestAttrWeight)}, Value: []byte{1, 0}},
			},
			wantErr: ErrTruncatedRecord,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := assembleDestination(tc.attrs)
			if err == nil {
				t.Fatalf("assembleDestination() = %+v, want error", got)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("assembleDestination() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestParseRouteAttrsRejectsTrailingGarbage(t *testing.T) {
	valid := nl.NewRtAttr(int(ipvsSvcAttrAddress), []byte{192, 0, 2, 1}).Serialize()

	t.Run("trailing bytes", func(t *testing.T) {
		_, err := parseRouteAttrs(append(valid, 1, 2))
		if !errors.Is(err, ErrTruncatedRecord) {
			t.Errorf("parseRouteAttrs() error = %v, want ErrTruncatedRecord", err)
		}
	})

	t.Run("length beyond buffer", func(t *testing.T) {
		msg := append([]byte{}, valid[:len(valid)-1]...)
		native.PutUint16(msg[:2], uint16(len(valid)+8)) //nolint:gosec // test value fits in uint16
		_, err := parseRouteAttrs(msg)
		if !errors.Is(err, ErrTruncatedRecord) {
			t.Errorf("parseRouteAttrs() error = %v, want ErrTruncatedRecord", err)
		}
	})

	t.Run("length below header", func(t *testing.T) {
		msg := append([]byte{}, valid...)
		native.PutUint16(msg[:2], 2)
		_, err := parseRouteAttrs(msg)
		if !errors.Is(err, ErrMalformedRecord) {
			t.Errorf("parseRouteAttrs() error = %v, want ErrMalformedRecord", err)
		}
	})
}

// TestGetServicesPartialConcurrent reads the same handle from multiple
// goroutines; every caller must see an intact, ordered response, and the
// handle must serialize the request/reply cycles.
func TestGetServicesPartialConcurrent(t *testing.T) {
	const readers = 16
	const iterations = 50

	payloads := [][]byte{
		validServiceRecord(t, 1),
		nil,
		validServiceRecord(t, 2),
		validServiceRecord(t, 3),
	}

	var calls atomic.Int64
	var inFlight, maxInFlight atomic.Int64
	h := &Handle{
		executeFn: func(*nl.NetlinkRequest) ([][]byte, error) {
			calls.Add(1)
			n := inFlight.Add(1)
			for {
				previous := maxInFlight.Load()
				if n <= previous || maxInFlight.CompareAndSwap(previous, n) {
					break
				}
			}
			defer inFlight.Add(-1)
			// Widen the window in which an unserialized implementation
			// would interleave its request/reply cycles.
			time.Sleep(time.Millisecond)
			return payloads, nil
		},
	}

	var wg sync.WaitGroup
	errs := make(chan error, readers)
	for n := 0; n < readers; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				services, err := h.GetServicesPartial()
				if !errors.Is(err, ErrTruncatedRecord) {
					errs <- fmt.Errorf("error = %v, want ErrTruncatedRecord", err)
					return
				}
				var got []string
				for _, svc := range services {
					got = append(got, svc.Address.String())
				}
				if want := "[192.0.2.1 192.0.2.2 192.0.2.3]"; fmt.Sprint(got) != want {
					errs <- fmt.Errorf("services = %v, want %s", got, want)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got, want := calls.Load(), int64(readers*iterations); got != want {
		t.Errorf("execute callback called %d times, want %d", got, want)
	}
	if got := maxInFlight.Load(); got != 1 {
		t.Errorf("up to %d queries ran concurrently, want 1 (handle must serialize socket access)", got)
	}
}

func TestGetServicesPartialTransportError(t *testing.T) {
	// Errors that are not decoding failures must not be reported as partial
	// results, and must not come with records.
	wantErr := errors.New("netlink socket closed")
	h := &Handle{executeFn: func(*nl.NetlinkRequest) ([][]byte, error) {
		return nil, wantErr
	}}

	services, err := h.GetServicesPartial()
	if !errors.Is(err, wantErr) {
		t.Fatalf("GetServicesPartial() error = %v, want %v", err, wantErr)
	}
	var partial *PartialResultError
	if errors.As(err, &partial) {
		t.Errorf("GetServicesPartial() error = %v, want no PartialResultError", err)
	}
	if services != nil {
		t.Errorf("GetServicesPartial() returned %d services alongside error, want none", len(services))
	}
}

func TestPartialResultErrorMessage(t *testing.T) {
	err := &PartialResultError{
		Resource: "service",
		Total:    3,
		Records: []*RecordError{
			{Index: 1, Err: fmt.Errorf("%w: bad", ErrMalformedRecord)},
			{Index: 2, Err: fmt.Errorf("%w: cut", ErrTruncatedRecord)},
		},
	}
	want := "ipvs: 2 of 3 service records could not be decoded: netlink record 1: ipvs: malformed netlink record: bad"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, ErrTruncatedRecord) || !errors.Is(err, ErrMalformedRecord) {
		t.Errorf("errors.Is did not match the per-record errors")
	}
}

func TestParseRouteAttrsAllowsTrailingPadding(t *testing.T) {
	// Two zero bytes of alignment padding after a complete attribute are
	// common at the end of a netlink buffer and must be ignored.
	valid := nl.NewRtAttr(int(ipvsSvcAttrAddress), []byte{192, 0, 2, 1}).Serialize()
	attrs, err := parseRouteAttrs(append(valid, 0, 0))
	if err != nil {
		t.Fatalf("parseRouteAttrs() error = %v, want nil", err)
	}
	if len(attrs) != 1 {
		t.Fatalf("len(attrs) = %d, want 1", len(attrs))
	}
}

func TestAssembleServiceByteOrderAttributes(t *testing.T) {
	// The kernel encodes NETMASK with nla_put_be32, which sets
	// NLA_F_NET_BYTEORDER and stores the value big-endian.
	bigEndianNetmask := []byte{0xff, 0xff, 0xff, 0x00}

	got, err := assembleService([]syscall.NetlinkRouteAttr{
		{Attr: syscall.RtAttr{Type: uint16(ipvsSvcAttrAddressFamily)}, Value: nl.Uint16Attr(unix.AF_INET)},
		{Attr: syscall.RtAttr{Type: uint16(ipvsSvcAttrAddress)}, Value: []byte{192, 0, 2, 1}},
		{Attr: syscall.RtAttr{Type: uint16(ipvsSvcAttrNetmask) | unix.NLA_F_NET_BYTEORDER}, Value: bigEndianNetmask},
	})
	if err != nil {
		t.Fatalf("assembleService() error = %v, want nil", err)
	}
	if want := uint32(0xffffff00); got.Netmask != want {
		t.Errorf("Netmask = %#x, want %#x", got.Netmask, want)
	}
}
