package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	setProxy("localhost:8888", "")
}

func winStr(str string) uintptr {
	return uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(str)))
}

func setProxy(strProxy, exceptions string) bool {

	// USE a proxy server ...
	options := []InternetConnectionOption{}

	options[0].m_Option = INTERNET_PER_CONN_FLAGS
	if strProxy != "" { // use THIS proxy server
		options[0].m_Value.m_Int = PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY
		options[1].m_Option = INTERNET_PER_CONN_PROXY_SERVER
		options[1].m_Value.m_StringPtr = winStr(strProxy)
		if exceptions != "" { // except for these addresses ...
			options[2].m_Option = INTERNET_PER_CONN_PROXY_BYPASS
			options[2].m_Value.m_StringPtr = winStr(exceptions)
		}
	} else {
		options[0].m_Value.m_Int = PROXY_TYPE_DIRECT
	}
	list := InternetPerConnOptionList{uint32(unsafe.Sizeof(options)), 0, uint32(len(options)), 0, options}

	var winInet = syscall.NewLazyDLL("WinInet.dll")
	var proc = winInet.NewProc("InternetSetOption")
	ret, _, err := proc.Call(0, INTERNET_OPTION_PER_CONNECTION_OPTION, uintptr(unsafe.Pointer(&list)), unsafe.Sizeof(list))
	if err != nil {
		fmt.Println(err)
	}
	return ret > 0
}

type InternetPerConnOptionList struct {
	dwSize        uint32  // size of the INTERNET_PER_CONN_OPTION_LIST struct
	pszConnection uintptr // connection name to set/query options
	dwOptionCount uint32  // number of options to set/query
	dwOptionError uint32  // on error, which option failed
	options       []InternetConnectionOption
}

type InternetConnectionOption struct {
	Size     uint32
	m_Option uint32
	m_Value  InternetConnectionOptionValue
}

type InternetConnectionOptionValue struct {
	m_FileTime  FILETIME
	m_Int       uint32
	m_StringPtr uintptr
}

type FILETIME struct {
	DwLowDateTime  uint32
	DwHighDateTime uint32
}

const (
	// options manifests for Internet{Query|Set}Option
	INTERNET_OPTION_REFRESH               = 37
	INTERNET_OPTION_SETTINGS_CHANGED      = 39
	INTERNET_OPTION_PER_CONNECTION_OPTION = 75

	// Options used in INTERNET_PER_CONN_OPTON struct
	INTERNET_PER_CONN_FLAGS          = 1 // Sets or retrieves the connection type. The Value member will contain one or more of the values from PerConnFlags
	INTERNET_PER_CONN_PROXY_SERVER   = 2 // Sets or retrieves a string containing the proxy servers.
	INTERNET_PER_CONN_PROXY_BYPASS   = 3 // Sets or retrieves a string containing the URLs that do not use the proxy server.
	INTERNET_PER_CONN_AUTOCONFIG_URL = 4 // Sets or retrieves a string containing the URL to the automatic configuration script.

	// PER_CONN_FLAGS
	PROXY_TYPE_DIRECT         = 0x00000001 // direct to net
	PROXY_TYPE_PROXY          = 0x00000002 // via named proxy
	PROXY_TYPE_AUTO_PROXY_URL = 0x00000004 // autoproxy URL
	PROXY_TYPE_AUTO_DETECT    = 0x00000008 // use autoproxy detection
)
