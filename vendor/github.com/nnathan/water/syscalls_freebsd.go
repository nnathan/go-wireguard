// +build freebsd

package water

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const tuntapMax = 256

func newTAP(ifName string) (ifce *Interface, err error) {
	var file *os.File

	start, end := 0, tuntapMax

	// user specifies the interface name (e.g. tap5)
	if ifName != "" {
		if !strings.HasPrefix(ifName, "tap") {
			return nil, fmt.Errorf("interface name must have 'tap' as prefix (%s)", ifName)
		}

		i, err := strconv.Atoi(ifName[3:])
		if err != nil {
			return nil, fmt.Errorf("interface name must have numeric suffix (%s)", ifName)
		}

		start, end = i, i+1
	}

	for i := start; i < end; i++ {
		ifName = "tap" + strconv.Itoa(i)
		file, err = os.OpenFile("/dev/"+ifName, os.O_RDWR, 0)
		if err == nil {
			break
		}
	}

	return &Interface{isTAP: true, ReadWriteCloser: file, name: ifName}, err
}

func newTUN(ifName string) (ifce *Interface, err error) {
	var file *os.File

	start, end := 0, tuntapMax

	// user specifies the interface name (e.g. tap5)
	if ifName != "" {
		if !strings.HasPrefix(ifName, "tun") {
			return nil, fmt.Errorf("interface name must have 'tun' as prefix (%s)", ifName)
		}

		i, err := strconv.Atoi(ifName[3:])
		if err != nil {
			return nil, fmt.Errorf("interface name must have numeric suffix (%s)", ifName)
		}

		start, end = i, i+1
	}

	for i := start; i < end; i++ {
		ifName = "tun" + strconv.Itoa(i)
		file, err = os.OpenFile("/dev/"+ifName, os.O_RDWR, 0)
		if err == nil {
			break
		}
	}

	return &Interface{isTAP: false, ReadWriteCloser: file, name: ifName}, err
}
