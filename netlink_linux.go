package ipvs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// For Quick Reference IPVS related netlink message is described at the end of this file.
var native = nl.NativeEndian()

// genlMsgHdrLen is the serialized size of genlMsgHdr. Keep this explicit
// rather than deriving it with unsafe.Sizeof so the wire format does not
// depend on the Go struct representation.
const genlMsgHdrLen = 4

type genlMsgHdr struct {
	cmd      uint8
	version  uint8
	reserved uint16
}

// ipvsFlagsLen is the serialized size of ipvsFlags. Keep this explicit
// rather than deriving it with unsafe.Sizeof so the wire format does not
// depend on the Go struct representation.
const ipvsFlagsLen = 8

type ipvsFlags struct {
	flags uint32
	mask  uint32
}

func (hdr *genlMsgHdr) Serialize() []byte {
	b := make([]byte, genlMsgHdrLen)
	b[0] = hdr.cmd
	b[1] = hdr.version
	native.PutUint16(b[2:], hdr.reserved)
	return b
}

func (*genlMsgHdr) Len() int {
	return genlMsgHdrLen
}

func (f *ipvsFlags) Serialize() []byte {
	b := make([]byte, ipvsFlagsLen)
	native.PutUint32(b[0:], f.flags)
	native.PutUint32(b[4:], f.mask)
	return b
}

func (*ipvsFlags) Len() int {
	return ipvsFlagsLen
}

// ipvsFamily lazily discovers and caches the IPVS generic-netlink family ID
// and any initialization error.
var ipvsFamily = sync.OnceValues(func() (int, error) {
	family, err := getIPVSFamily()
	if err == nil {
		return family, nil
	}

	// Linux 5.17 added automatic loading of ip_vs through generic-netlink
	// family discovery. Older kernels, including RHEL 8's 4.18 kernel,
	// may still require explicit module loading.
	//
	// See https://lists.openwall.net/netdev/2021/11/01/229
	output, modprobeErr := exec.Command("modprobe", "-va", "ip_vs").CombinedOutput()

	family, err = getIPVSFamily()
	if err != nil {
		err = fmt.Errorf("get IPVS generic-netlink family: %w", err)
		if modprobeErr != nil && !errors.Is(modprobeErr, exec.ErrNotFound) {
			err = errors.Join(err, fmt.Errorf("modprobe ip_vs: %w: %s", modprobeErr, bytes.TrimSpace(output)))
		}
		return 0, err
	}
	return family, nil
})

func fillService(s *Service) nl.NetlinkRequestData {
	cmdAttr := nl.NewRtAttr(int(ipvsCmdAttrService), nil)
	cmdAttr.AddRtAttr(int(ipvsSvcAttrAddressFamily), nl.Uint16Attr(s.AddressFamily))
	if s.FWMark != 0 {
		cmdAttr.AddRtAttr(int(ipvsSvcAttrFWMark), nl.Uint32Attr(s.FWMark))
	} else {
		cmdAttr.AddRtAttr(int(ipvsSvcAttrProtocol), nl.Uint16Attr(s.Protocol))
		cmdAttr.AddRtAttr(int(ipvsSvcAttrAddress), rawIPData(s.Address))

		// Port needs to be in network byte order.
		var portBuf bytes.Buffer
		_ = binary.Write(&portBuf, binary.BigEndian, s.Port)
		cmdAttr.AddRtAttr(int(ipvsSvcAttrPort), portBuf.Bytes())
	}

	cmdAttr.AddRtAttr(int(ipvsSvcAttrSchedName), nl.ZeroTerminated(s.SchedName))
	if s.PEName != "" {
		cmdAttr.AddRtAttr(int(ipvsSvcAttrPEName), nl.ZeroTerminated(s.PEName))
	}
	f := &ipvsFlags{
		flags: s.Flags,
		mask:  0xFFFFFFFF,
	}
	cmdAttr.AddRtAttr(int(ipvsSvcAttrFlags), f.Serialize())
	cmdAttr.AddRtAttr(int(ipvsSvcAttrTimeout), nl.Uint32Attr(s.Timeout))
	cmdAttr.AddRtAttr(int(ipvsSvcAttrNetmask), nl.Uint32Attr(s.Netmask))
	return cmdAttr
}

func fillDestination(d *Destination) (nl.NetlinkRequestData, error) {
	if d.Weight < 0 || d.Weight > math.MaxInt32 {
		return nil, fmt.Errorf("destination weight out of range: %d", d.Weight)
	}
	cmdAttr := nl.NewRtAttr(int(ipvsCmdAttrDest), nil)

	cmdAttr.AddRtAttr(int(ipvsDestAttrAddress), rawIPData(d.Address))
	// Port needs to be in network byte order.
	var portBuf bytes.Buffer
	_ = binary.Write(&portBuf, binary.BigEndian, d.Port)
	cmdAttr.AddRtAttr(int(ipvsDestAttrPort), portBuf.Bytes())
	cmdAttr.AddRtAttr(int(ipvsDestAttrForwardingMethod), nl.Uint32Attr(d.ConnectionFlags&ConnFwdMask))
	cmdAttr.AddRtAttr(int(ipvsDestAttrWeight), nl.Uint32Attr(uint32(d.Weight)))
	cmdAttr.AddRtAttr(int(ipvsDestAttrUpperThreshold), nl.Uint32Attr(d.UpperThreshold))
	cmdAttr.AddRtAttr(int(ipvsDestAttrLowerThreshold), nl.Uint32Attr(d.LowerThreshold))

	return cmdAttr, nil
}

func (i *Handle) doCmdwithResponse(s *Service, d *Destination, cmd ipvsCmd) ([][]byte, error) {
	req := newIPVSRequest(cmd)
	req.Seq = atomic.AddUint32(&i.seq, 1)

	if s == nil {
		req.Flags |= syscall.NLM_F_DUMP                         // Flag to dump all messages
		req.AddData(nl.NewRtAttr(int(ipvsCmdAttrService), nil)) // Add a dummy attribute
	} else {
		req.AddData(fillService(s))
	}

	if d == nil {
		if cmd == ipvsCmdGetDest {
			req.Flags |= syscall.NLM_F_DUMP
		}
	} else {
		attr, err := fillDestination(d)
		if err != nil {
			return nil, err
		}
		req.AddData(attr)
	}

	res, err := i.doExecute(req)
	if err != nil {
		return [][]byte{}, err
	}

	return res, nil
}

// doExecute sends req on the handle's netlink socket and returns the raw
// response payloads. It serializes access to the socket so that concurrent
// queries on the same handle do not interleave their request/reply cycles.
func (i *Handle) doExecute(req *nl.NetlinkRequest) ([][]byte, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.executeFn != nil {
		return i.executeFn(req)
	}
	return execute(i.sock, req)
}

func (i *Handle) doCmd(s *Service, d *Destination, cmd ipvsCmd) error {
	_, err := i.doCmdwithResponse(s, d, cmd)

	return err
}

func getIPVSFamily() (int, error) {
	sock, err := nl.GetNetlinkSocketAt(netns.None(), netns.None(), syscall.NETLINK_GENERIC)
	if err != nil {
		return 0, err
	}
	defer sock.Close()

	req := newGenlRequest(genlCtrlID, genlCtrlCmdGetFamily)
	req.AddData(nl.NewRtAttr(genlCtrlAttrFamilyName, nl.ZeroTerminated("IPVS")))

	msgs, err := execute(sock, req)
	if err != nil {
		return 0, err
	}

	for _, m := range msgs {
		if len(m) < genlMsgHdrLen {
			return 0, errors.New("invalid generic netlink response: message too short")
		}

		attrs, err := nl.ParseRouteAttr(m[genlMsgHdrLen:])
		if err != nil {
			return 0, err
		}

		for _, attr := range attrs {
			if int(attr.Attr.Type) != genlCtrlAttrFamilyID {
				continue
			}
			if len(attr.Value) < 2 {
				return 0, errors.New("invalid generic netlink response: family ID too short")
			}
			return int(native.Uint16(attr.Value[:2])), nil
		}
	}

	return 0, errors.New("no family id in the netlink response")
}

func rawIPData(ip net.IP) []byte {
	family := nl.GetIPFamily(ip)
	if family == unix.AF_INET {
		return ip.To4()
	}
	return ip
}

func newIPVSRequest(cmd ipvsCmd) *nl.NetlinkRequest {
	family, _ := ipvsFamily()
	return newGenlRequest(family, uint8(cmd))
}

func newGenlRequest(familyID int, cmd uint8) *nl.NetlinkRequest {
	req := nl.NewNetlinkRequest(familyID, syscall.NLM_F_ACK)
	req.AddData(&genlMsgHdr{cmd: cmd, version: 1})
	return req
}

// execute sends req over s and collects the response payloads of the dump.
func execute(s *nl.NetlinkSocket, req *nl.NetlinkRequest) ([][]byte, error) {
	if err := s.Send(req); err != nil {
		return nil, err
	}

	pid, err := s.GetPid()
	if err != nil {
		return nil, err
	}

	var res [][]byte

done:
	for {
		msgs, _, err := s.Receive()
		if err != nil {
			if s.GetFd() == -1 {
				return nil, errors.New("socket got closed on receive")
			}
			if err == syscall.EAGAIN {
				// timeout fired
				continue
			}
			return nil, err
		}
		for _, m := range msgs {
			if m.Header.Seq != req.Seq {
				continue
			}
			if m.Header.Pid != pid {
				return nil, fmt.Errorf("wrong pid %d, expected %d", m.Header.Pid, pid)
			}
			if m.Header.Type == syscall.NLMSG_DONE {
				break done
			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				if len(m.Data) < 4 {
					return nil, errors.New("invalid netlink error response: message too short")
				}
				errno := native.Uint32(m.Data[:4])
				if errno == 0 {
					break done
				}
				return nil, syscall.Errno(-errno)
			}
			res = append(res, m.Data)
			if m.Header.Flags&syscall.NLM_F_MULTI == 0 {
				break done
			}
		}
	}
	return res, nil
}

func parseIP(ip []byte, family uint16) (net.IP, error) {
	switch family {
	case syscall.AF_INET:
		if len(ip) < net.IPv4len {
			return nil, fmt.Errorf("%w: invalid IPv4 address: %d bytes", ErrTruncatedRecord, len(ip))
		}
		return ip[:net.IPv4len], nil
	case syscall.AF_INET6:
		if len(ip) < net.IPv6len {
			return nil, fmt.Errorf("%w: invalid IPv6 address: %d bytes", ErrTruncatedRecord, len(ip))
		}
		return ip[:net.IPv6len], nil
	default:
		return nil, fmt.Errorf("%w: unsupported address family: %d", ErrUnknownAddressFamily, family)
	}
}

// attrUint16, attrUint32, and attrUint64 decode fixed-width attribute values,
// rejecting attributes that are too short instead of letting the binary
// package panic or silently read adjacent memory. Values carrying
// NLA_F_NET_BYTEORDER are decoded as big-endian, as the kernel writes them
// with nla_put_net*.
func attrOrder(attr syscall.NetlinkRouteAttr) binary.ByteOrder {
	if attr.Attr.Type&unix.NLA_F_NET_BYTEORDER != 0 {
		return binary.BigEndian
	}
	return native
}

func attrUint16(attr syscall.NetlinkRouteAttr) (uint16, error) {
	if len(attr.Value) < 2 {
		return 0, fmt.Errorf("%w: attribute type %d has %d bytes, need 2",
			ErrTruncatedRecord, attrType(attr.Attr.Type), len(attr.Value))
	}
	return attrOrder(attr).Uint16(attr.Value), nil
}

func attrUint32(attr syscall.NetlinkRouteAttr) (uint32, error) {
	if len(attr.Value) < 4 {
		return 0, fmt.Errorf("%w: attribute type %d has %d bytes, need 4",
			ErrTruncatedRecord, attrType(attr.Attr.Type), len(attr.Value))
	}
	return attrOrder(attr).Uint32(attr.Value), nil
}

func attrUint64(attr syscall.NetlinkRouteAttr) (uint64, error) {
	if len(attr.Value) < 8 {
		return 0, fmt.Errorf("%w: attribute type %d has %d bytes, need 8",
			ErrTruncatedRecord, attrType(attr.Attr.Type), len(attr.Value))
	}
	return attrOrder(attr).Uint64(attr.Value), nil
}

// attrPort decodes a port, which the kernel always transmits with
// nla_put_be16 - in network byte order, but without NLA_F_NET_BYTEORDER.
func attrPort(attr syscall.NetlinkRouteAttr) (uint16, error) {
	if len(attr.Value) < 2 {
		return 0, fmt.Errorf("%w: attribute type %d has %d bytes, need 2",
			ErrTruncatedRecord, attrType(attr.Attr.Type), len(attr.Value))
	}
	return binary.BigEndian.Uint16(attr.Value), nil
}

// attrString decodes a zero-terminated string attribute. Unlike
// nl.BytesToString it does not panic when the terminator is missing.
func attrString(attr syscall.NetlinkRouteAttr) string {
	if i := bytes.IndexByte(attr.Value, 0); i >= 0 {
		return string(attr.Value[:i])
	}
	return string(attr.Value)
}

// parseStats
func assembleStats(msg []byte) (SvcStats, error) {
	var s SvcStats

	attrs, err := parseRouteAttrs(msg)
	if err != nil {
		return s, err
	}

	for _, attr := range attrs {
		var err error
		switch ipvsStats(attrType(attr.Attr.Type)) {
		case ipvsStatsUnspec:
			// unspecified
		case ipvsStatsConns:
			s.Connections, err = attrUint32(attr)
		case ipvsStatsPktsIn:
			s.PacketsIn, err = attrUint32(attr)
		case ipvsStatsPktsOut:
			s.PacketsOut, err = attrUint32(attr)
		case ipvsStatsBytesIn:
			s.BytesIn, err = attrUint64(attr)
		case ipvsStatsBytesOut:
			s.BytesOut, err = attrUint64(attr)
		case ipvsStatsCPS:
			s.CPS, err = attrUint32(attr)
		case ipvsStatsPPSIn:
			s.PPSIn, err = attrUint32(attr)
		case ipvsStatsPPSOut:
			s.PPSOut, err = attrUint32(attr)
		case ipvsStatsBPSIn:
			s.BPSIn, err = attrUint32(attr)
		case ipvsStatsBPSOut:
			s.BPSOut, err = attrUint32(attr)
		}
		if err != nil {
			return SvcStats{}, err
		}
	}
	return s, nil
}

// assembleService assembles a service back from a chain of netlink attributes.
// Records missing an address family, or missing the address of an
// address-based (non-firewall-mark) service, are rejected instead of being
// returned as partly zero-valued services.
func assembleService(attrs []syscall.NetlinkRouteAttr) (*Service, error) {
	var s Service
	var addressBytes []byte
	var (
		haveFamily  bool
		haveAddress bool
		haveFWMark  bool
	)

	for _, attr := range attrs {
		var err error
		switch ipvsSvcAttr(attrType(attr.Attr.Type)) {
		case ipvsSvcAttrUnspec:
			// unspecified
		case ipvsSvcAttrAddressFamily:
			s.AddressFamily, err = attrUint16(attr)
			haveFamily = true
		case ipvsSvcAttrProtocol:
			s.Protocol, err = attrUint16(attr)
		case ipvsSvcAttrAddress:
			addressBytes = attr.Value
			haveAddress = true
		case ipvsSvcAttrPort:
			s.Port, err = attrPort(attr)
		case ipvsSvcAttrFWMark:
			s.FWMark, err = attrUint32(attr)
			haveFWMark = true
		case ipvsSvcAttrSchedName:
			s.SchedName = attrString(attr)
		case ipvsSvcAttrFlags:
			s.Flags, err = attrUint32(attr)
		case ipvsSvcAttrTimeout:
			s.Timeout, err = attrUint32(attr)
		case ipvsSvcAttrNetmask:
			s.Netmask, err = attrUint32(attr)
		case ipvsSvcAttrPEName:
			s.PEName = attrString(attr)
		case ipvsSvcAttrStats:
			var stats SvcStats
			stats, err = assembleStats(attr.Value)
			if err == nil {
				s.Stats = stats
			}
		}
		if err != nil {
			return nil, err
		}
	}

	if !haveFamily {
		return nil, fmt.Errorf("%w: service record has no address family attribute", ErrMissingAttribute)
	}
	switch s.AddressFamily {
	case syscall.AF_INET, syscall.AF_INET6:
		// supported; address parsing below validates the length.
	default:
		return nil, fmt.Errorf("%w: service record has unsupported address family %d",
			ErrUnknownAddressFamily, s.AddressFamily)
	}

	// Address-based services carry an address; firewall-mark services do not.
	if !haveAddress {
		if !haveFWMark {
			return nil, fmt.Errorf("%w: service record has neither address nor firewall mark", ErrMissingAttribute)
		}
		return &s, nil
	}

	ip, err := parseIP(addressBytes, s.AddressFamily)
	if err != nil {
		return nil, err
	}
	s.Address = ip

	return &s, nil
}

// parseService given a ipvs netlink response this function will respond with a valid service entry, an error otherwise
func (i *Handle) parseService(msg []byte) (*Service, error) {
	var s *Service

	// Remove General header for this message and parse the NetLink message
	if len(msg) < genlMsgHdrLen {
		return nil, fmt.Errorf("%w: invalid generic netlink response: message too short", ErrTruncatedRecord)
	}
	msgAttrs, err := parseRouteAttrs(msg[genlMsgHdrLen:])
	if err != nil {
		return nil, err
	}
	if len(msgAttrs) == 0 {
		return nil, fmt.Errorf("%w: no service attribute in netlink response", ErrMissingAttribute)
	}

	// The service is nested in an IPVS_CMD_ATTR_SERVICE attribute.
	cmdAttr := msgAttrs[0]
	if attrType(cmdAttr.Attr.Type) != uint16(ipvsCmdAttrService) {
		return nil, fmt.Errorf("%w: expected service attribute, got attribute type %d", ErrMalformedRecord, attrType(cmdAttr.Attr.Type))
	}

	// Now Parse and get IPVS related attributes messages packed in this message.
	ipvsAttrs, err := parseRouteAttrs(cmdAttr.Value)
	if err != nil {
		return nil, err
	}
	if len(ipvsAttrs) == 0 {
		return nil, fmt.Errorf("%w: no valid netlink message found while parsing service record", ErrMissingAttribute)
	}

	// Assemble all the IPVS related attribute messages and create a service record
	s, err = assembleService(ipvsAttrs)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// parseRouteAttrs parses a sequence of netlink attributes. Unlike
// nl.ParseRouteAttr it rejects trailing bytes that cannot form a complete
// attribute, and reports attributes whose payload is cut short with
// ErrTruncatedRecord, so that a cut-off response is never silently accepted as
// a valid record. Zero padding at the end of the buffer is allowed, as the
// kernel may not pad the final attribute's payload to a 4-byte boundary.
func parseRouteAttrs(b []byte) ([]syscall.NetlinkRouteAttr, error) {
	var attrs []syscall.NetlinkRouteAttr

	for len(b) > 0 {
		if len(b) < unix.SizeofRtAttr {
			if isZeros(b) {
				// Trailing alignment padding, not an attribute.
				break
			}
			return nil, fmt.Errorf("%w: %d trailing bytes cannot form a netlink attribute", ErrTruncatedRecord, len(b))
		}
		attrLen := int(native.Uint16(b[:2]))
		if attrLen < unix.SizeofRtAttr {
			return nil, fmt.Errorf("%w: netlink attribute length %d is smaller than its header", ErrMalformedRecord, attrLen)
		}
		if attrLen > len(b) {
			return nil, fmt.Errorf("%w: netlink attribute claims %d bytes, %d available", ErrTruncatedRecord, attrLen, len(b))
		}

		// attrLen was read from a uint16, so it always fits back into one.
		attrs = append(attrs, syscall.NetlinkRouteAttr{
			Attr:  syscall.RtAttr{Len: uint16(attrLen), Type: native.Uint16(b[2:4])}, //nolint:gosec // attrLen is a decoded uint16
			Value: b[unix.SizeofRtAttr:attrLen],
		})

		aligned := rtaAlignOf(attrLen)
		if aligned > len(b) {
			if !isZeros(b[attrLen:]) {
				return nil, fmt.Errorf("%w: netlink attribute claims %d aligned bytes, %d available", ErrTruncatedRecord, aligned, len(b))
			}
			break
		}
		b = b[aligned:]
	}

	return attrs, nil
}

func rtaAlignOf(attrLen int) int {
	return (attrLen + unix.SizeofRtAttr - 1) &^ (unix.SizeofRtAttr - 1)
}

// attrType strips the netlink attribute flags from a type, leaving the
// attribute identifier. The flags are not part of the attribute's identity:
// the kernel marks nested attributes (NLA_F_NESTED) and network-byte-order
// values (NLA_F_NET_BYTEORDER), so the raw type must be masked before it is
// compared against the IPVS attribute constants. The byte-order flag still
// affects how a value is decoded; see attrOrder.
func attrType(t uint16) uint16 {
	return t &^ uint16(unix.NLA_F_NESTED|unix.NLA_F_NET_BYTEORDER)
}

// doGetServicesCmd a wrapper which could be used commonly for both GetServices() and GetService(*Service).
//
// GetServices has always failed without returning any records when a record
// cannot be decoded, so the decoded prefix is discarded here.
func (i *Handle) doGetServicesCmd(svc *Service) ([]*Service, error) {
	msgs, err := i.doCmdwithResponse(svc, nil, ipvsCmdGetService)
	if err != nil {
		return nil, err
	}

	res, err := decodeRecordsStrict(msgs, "service", i.parseService)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// doGetServicesPartialCmd decodes all service records in a dump response,
// keeping valid records and reporting invalid ones individually.
func (i *Handle) doGetServicesPartialCmd(svc *Service) ([]*Service, error) {
	msgs, err := i.doCmdwithResponse(svc, nil, ipvsCmdGetService)
	if err != nil {
		return nil, err
	}

	return decodeRecordsPartial(msgs, "service", i.parseService)
}

// decodeRecordsStrict decodes records in a dump response and stops at the
// first record that cannot be decoded. The records decoded before the failure
// are returned together with an error identifying the failing record.
//
// Callers decide whether to expose that prefix: GetServices discards it (as it
// always has), while GetDestinations has historically returned it alongside
// the error.
func decodeRecordsStrict[T any](msgs [][]byte, resource string, parse func([]byte) (*T, error)) ([]*T, error) {
	res := make([]*T, 0, len(msgs))
	for index, msg := range msgs {
		record, err := parse(msg)
		if err != nil {
			return res, fmt.Errorf("parse %s record %d: %w", resource, index, err)
		}
		res = append(res, record)
	}
	return res, nil
}

// decodeRecordsPartial decodes every record in a dump response in order. Valid
// records are returned in netlink response order; invalid records are skipped
// and reported together as a *PartialResultError. Indexes refer to positions
// in the full response, so a skipped record does not shift the indexes of the
// records that follow it.
func decodeRecordsPartial[T any](msgs [][]byte, resource string, parse func([]byte) (*T, error)) ([]*T, error) {
	res := make([]*T, 0, len(msgs))
	var recordErrs []*RecordError

	for index, msg := range msgs {
		record, err := parse(msg)
		if err != nil {
			recordErrs = append(recordErrs, &RecordError{Index: index, Err: err})
			continue
		}
		res = append(res, record)
	}

	if len(recordErrs) > 0 {
		return res, &PartialResultError{
			Resource: resource,
			Total:    len(msgs),
			Records:  recordErrs,
		}
	}
	return res, nil
}

// doCmdWithoutAttr a simple wrapper of netlink socket execute command
func (i *Handle) doCmdWithoutAttr(cmd ipvsCmd) ([][]byte, error) {
	req := newIPVSRequest(cmd)
	req.Seq = atomic.AddUint32(&i.seq, 1)
	return i.doExecute(req)
}

// assembleDestination assembles a destination back from a chain of netlink
// attributes. Records without an address are rejected instead of being
// returned as partly zero-valued destinations.
func assembleDestination(attrs []syscall.NetlinkRouteAttr) (*Destination, error) {
	var d Destination
	var addressBytes []byte
	var haveAddress bool

	for _, attr := range attrs {
		var err error
		switch ipvsDestAttr(attrType(attr.Attr.Type)) {
		case ipvsDestAttrUnspec:
			// unspecified
		case ipvsDestAttrAddressFamily:
			d.AddressFamily, err = attrUint16(attr)
		case ipvsDestAttrAddress:
			addressBytes = attr.Value
			haveAddress = true
		case ipvsDestAttrPort:
			d.Port, err = attrPort(attr)
		case ipvsDestAttrForwardingMethod:
			d.ConnectionFlags, err = attrUint32(attr)
		case ipvsDestAttrWeight:
			var weight uint32
			weight, err = attrUint32(attr)
			d.Weight = int(weight)
		case ipvsDestAttrUpperThreshold:
			d.UpperThreshold, err = attrUint32(attr)
		case ipvsDestAttrLowerThreshold:
			d.LowerThreshold, err = attrUint32(attr)
		case ipvsDestAttrActiveConnections:
			var active uint32
			active, err = attrUint32(attr)
			d.ActiveConnections = int(active)
		case ipvsDestAttrInactiveConnections:
			var inactive uint32
			inactive, err = attrUint32(attr)
			d.InactiveConnections = int(inactive)
		case ipvsDestAttrPersistentConnections:
			var persistent uint32
			persistent, err = attrUint32(attr)
			d.PersistentConnections = int(persistent)
		case ipvsDestAttrStats:
			var stats SvcStats
			stats, err = assembleStats(attr.Value)
			if err == nil {
				d.Stats = DstStats(stats)
			}
		}
		if err != nil {
			return nil, err
		}
	}

	if !haveAddress {
		return nil, fmt.Errorf("%w: destination record has no address attribute", ErrMissingAttribute)
	}

	// In older kernels (< 3.18), the destination address family attribute
	// doesn't exist, so it must be inferred from the address data.
	if d.AddressFamily == 0 {
		// we can't check the address family using net stdlib because netlink returns
		// IPv4 addresses as the first 4 bytes in a []byte of length 16 where as
		// stdlib expects it as the last 4 bytes.
		addressFamily, err := getIPFamily(addressBytes)
		if err != nil {
			return nil, err
		}
		d.AddressFamily = addressFamily
	}

	ip, err := parseIP(addressBytes, d.AddressFamily)
	if err != nil {
		return nil, err
	}
	d.Address = ip

	return &d, nil
}

// getIPFamily parses the IP family based on raw data from netlink.
// For AF_INET, netlink will set the first 4 bytes with trailing zeros
//
//	10.0.0.1 -> [10 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0]
//
// For AF_INET6, the full 16 byte array is used:
//
//	2001:db8:3c4d:15::1a00 -> [32 1 13 184 60 77 0 21 0 0 0 0 0 0 26 0]
func getIPFamily(address []byte) (uint16, error) {
	if len(address) == 4 {
		return syscall.AF_INET, nil
	}

	// An address shorter than the IPv4 header cannot carry a family.
	if len(address) < net.IPv4len {
		return 0, fmt.Errorf("%w: address data too short: %d bytes", ErrTruncatedRecord, len(address))
	}

	if isZeros(address) {
		// Keep the historical error value: getIPFamily has long reported
		// this exact error for an address without a usable family.
		return 0, errors.New("could not parse IP family from address data")
	}

	// assume IPv4 if first 4 bytes are non-zero but rest of the data is trailing zeros
	if !isZeros(address[:4]) && isZeros(address[4:]) {
		return syscall.AF_INET, nil
	}

	return syscall.AF_INET6, nil
}

func isZeros(b []byte) bool {
	for i := 0; i < len(b); i++ {
		if b[i] != 0 {
			return false
		}
	}
	return true
}

// parseDestination given a ipvs netlink response this function will respond with a valid destination entry, an error otherwise
func (i *Handle) parseDestination(msg []byte) (*Destination, error) {
	var dst *Destination

	// Remove General header for this message
	if len(msg) < genlMsgHdrLen {
		return nil, fmt.Errorf("%w: invalid generic netlink response: message too short", ErrTruncatedRecord)
	}
	msgAttrs, err := parseRouteAttrs(msg[genlMsgHdrLen:])
	if err != nil {
		return nil, err
	}
	if len(msgAttrs) == 0 {
		return nil, fmt.Errorf("%w: no destination attribute in netlink response", ErrMissingAttribute)
	}

	// The destination is nested in an IPVS_CMD_ATTR_DEST attribute.
	cmdAttr := msgAttrs[0]
	if attrType(cmdAttr.Attr.Type) != uint16(ipvsCmdAttrDest) {
		return nil, fmt.Errorf("%w: expected destination attribute, got attribute type %d", ErrMalformedRecord, attrType(cmdAttr.Attr.Type))
	}

	// Now Parse and get IPVS related attributes messages packed in this message.
	ipvsAttrs, err := parseRouteAttrs(cmdAttr.Value)
	if err != nil {
		return nil, err
	}

	// Assemble netlink attributes and create a Destination record
	dst, err = assembleDestination(ipvsAttrs)
	if err != nil {
		return nil, err
	}

	return dst, nil
}

// doGetDestinationsCmd a wrapper function to be used by GetDestinations and GetDestination(d) apis
func (i *Handle) doGetDestinationsCmd(s *Service, d *Destination) ([]*Destination, error) {
	msgs, err := i.doCmdwithResponse(s, d, ipvsCmdGetDest)
	if err != nil {
		return nil, err
	}

	return decodeRecordsStrict(msgs, "destination", i.parseDestination)
}

// doGetDestinationsPartialCmd decodes all destination records in a dump
// response, keeping valid records and reporting invalid ones individually.
func (i *Handle) doGetDestinationsPartialCmd(s *Service, d *Destination) ([]*Destination, error) {
	msgs, err := i.doCmdwithResponse(s, d, ipvsCmdGetDest)
	if err != nil {
		return nil, err
	}

	return decodeRecordsPartial(msgs, "destination", i.parseDestination)
}

// parseConfig given a ipvs netlink response this function will respond with a valid config entry, an error otherwise
func (i *Handle) parseConfig(msg []byte) (*Config, error) {
	var c Config

	// Remove General header for this message
	if len(msg) < genlMsgHdrLen {
		return nil, fmt.Errorf("%w: invalid generic netlink response: message too short", ErrTruncatedRecord)
	}
	attrs, err := parseRouteAttrs(msg[genlMsgHdrLen:])
	if err != nil {
		return nil, err
	}

	for _, attr := range attrs {
		var value uint32
		var err error
		switch ipvsCmdAttr(attrType(attr.Attr.Type)) {
		case ipvsCmdAttrUnspec:
			// unspecified
		case ipvsCmdAttrTimeoutTCP:
			value, err = attrUint32(attr)
			c.TimeoutTCP = time.Duration(value) * time.Second
		case ipvsCmdAttrTimeoutTCPFin:
			value, err = attrUint32(attr)
			c.TimeoutTCPFin = time.Duration(value) * time.Second
		case ipvsCmdAttrTimeoutUDP:
			value, err = attrUint32(attr)
			c.TimeoutUDP = time.Duration(value) * time.Second
		case ipvsCmdAttrService, ipvsCmdAttrDest, ipvsCmdAttrDaemon:
			// not implemented
		}
		if err != nil {
			return nil, err
		}
	}

	return &c, nil
}

// doGetConfigCmd a wrapper function to be used by GetConfig
func (i *Handle) doGetConfigCmd() (*Config, error) {
	msg, err := i.doCmdWithoutAttr(ipvsCmdGetConfig)
	if err != nil {
		return nil, err
	}
	if len(msg) == 0 {
		return nil, fmt.Errorf("%w: empty configuration response", ErrTruncatedRecord)
	}

	res, err := i.parseConfig(msg[0])
	if err != nil {
		return res, err
	}
	return res, nil
}

// doSetConfigCmd a wrapper function to be used by SetConfig
func (i *Handle) doSetConfigCmd(c *Config) error {
	req := newIPVSRequest(ipvsCmdSetConfig)
	req.Seq = atomic.AddUint32(&i.seq, 1)

	req.AddData(nl.NewRtAttr(int(ipvsCmdAttrTimeoutTCP), nl.Uint32Attr(uint32(c.TimeoutTCP.Seconds()))))
	req.AddData(nl.NewRtAttr(int(ipvsCmdAttrTimeoutTCPFin), nl.Uint32Attr(uint32(c.TimeoutTCPFin.Seconds()))))
	req.AddData(nl.NewRtAttr(int(ipvsCmdAttrTimeoutUDP), nl.Uint32Attr(uint32(c.TimeoutUDP.Seconds()))))

	_, err := i.doExecute(req)

	return err
}

// IPVS related netlink message format explained

/* EACH NETLINK MSG is of the below format, this is what we will receive from execute() api.
   If we have multiple netlink objects to process like GetServices() etc., execute() will
   supply an array of this below object

            NETLINK MSG
|-----------------------------------|
    0        1        2        3
|--------|--------|--------|--------| -
| CMD ID |  VER   |    RESERVED     | |==> General Message Header represented by genlMsgHdr
|-----------------------------------| -
|    ATTR LEN     |   ATTR TYPE     | |
|-----------------------------------| |
|                                   | |
|              VALUE                | |
|     []byte Array of IPVS MSG      | |==> Attribute Message represented by syscall.NetlinkRouteAttr
|        PADDED BY 4 BYTES          | |
|                                   | |
|-----------------------------------| -


 Once We strip genlMsgHdr from above NETLINK MSG, we should parse the VALUE.
 VALUE will have an array of netlink attributes (syscall.NetlinkRouteAttr) such that each attribute will
 represent a "Service" or "Destination" object's field.  If we assemble these attributes we can construct
 Service or Destination.

            IPVS MSG
|-----------------------------------|
     0        1        2        3
|--------|--------|--------|--------|
|    ATTR LEN     |    ATTR TYPE    |
|-----------------------------------|
|                                   |
|                                   |
| []byte IPVS ATTRIBUTE  BY 4 BYTES |
|                                   |
|                                   |
|-----------------------------------|
           NEXT ATTRIBUTE
|-----------------------------------|
|    ATTR LEN     |    ATTR TYPE    |
|-----------------------------------|
|                                   |
|                                   |
| []byte IPVS ATTRIBUTE  BY 4 BYTES |
|                                   |
|                                   |
|-----------------------------------|
           NEXT ATTRIBUTE
|-----------------------------------|
|    ATTR LEN     |    ATTR TYPE    |
|-----------------------------------|
|                                   |
|                                   |
| []byte IPVS ATTRIBUTE  BY 4 BYTES |
|                                   |
|                                   |
|-----------------------------------|

*/
