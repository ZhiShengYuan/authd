package subnet

import "net"

const (
	DefaultIPv4MaskBits = 24
	DefaultIPv6MaskBits = 56
)

func Key(ip string, ipv4Bits, ipv6Bits int) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}

	if ip4 := parsed.To4(); ip4 != nil {
		return maskSubnet(ip4, ipv4Bits)
	}

	return maskSubnet(parsed, ipv6Bits)
}

func DefaultKey(ip string) string {
	return Key(ip, DefaultIPv4MaskBits, DefaultIPv6MaskBits)
}

func IsIPv4(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.To4() != nil
}

func maskSubnet(ip net.IP, bits int) string {
	if len(ip) == 0 {
		return ""
	}

	maskSize := bits
	if maskSize < 0 || maskSize > 128 {
		return ""
	}

	hostBits := len(ip)*8 - maskSize
	if hostBits < 0 {
		return ""
	}

	var mask net.IPMask
	if len(ip) == 4 {
		mask = net.CIDRMask(maskSize, 32)
	} else {
		mask = net.CIDRMask(maskSize, 128)
	}

	network := make(net.IP, len(ip))
	for i := range ip {
		network[i] = ip[i] & mask[i]
	}

	return network.String() + "/" + itoa(maskSize)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}

	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}

	return string(digits)
}
