package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func setWinInetProxy(proxy string) bool {
	var exceptions, autoconfig string
	var autodetect bool
	options := [4]InternetConnectionOption{}
	options[0].Option = INTERNET_PER_CONN_FLAGS
	options[1].Option = INTERNET_PER_CONN_PROXY_SERVER
	options[2].Option = INTERNET_PER_CONN_PROXY_BYPASS
	options[3].Option = INTERNET_PER_CONN_AUTOCONFIG_URL
	options[0].Value = PROXY_TYPE_DIRECT

	if proxy != "" {
		options[0].Value |= PROXY_TYPE_PROXY
		options[1].Value = uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(proxy)))
	}

	if exceptions != "" {
		options[2].Value = uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(exceptions)))
	}

	if autoconfig != "" {
		options[0].Value |= PROXY_TYPE_AUTO_PROXY_URL
		options[3].Value = uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(autoconfig)))
	}

	if autodetect {
		options[0].Value |= PROXY_TYPE_AUTO_DETECT
	}

	list := InternetPerConnOptionList{0, 0, uint32(4), 0, uintptr(unsafe.Pointer(&options))}
	list.dwSize = uint32(unsafe.Sizeof(list))

	var winInet = syscall.NewLazyDLL("WinInet.dll")
	var proc = winInet.NewProc("InternetSetOptionW")
	ret, _, err := proc.Call(0, uintptr(INTERNET_OPTION_PER_CONNECTION_OPTION), uintptr(unsafe.Pointer(&list)), uintptr(unsafe.Sizeof(list)))
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
	options       uintptr
}

type InternetConnectionOption struct {
	Option uint32
	Value  uintptr // in c this is UNION(DWORD, LPTSTR, FILETIME)
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
