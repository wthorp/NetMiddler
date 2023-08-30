//go:build windows

package main

import (
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

func enableProxy(addrPort string) error {
	fmt.Println("Setting up proxy on localhost:8888")
	setWinInetProxy(addrPort)
	setWinEnvProxy(addrPort)
}

func disableProxy() {
	fmt.Println("Cleaning up proxy")
	setWinInetProxy("")
	setWinEnvProxy("")
}

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

const (
	envText          = "Environment"
	HWND_BROADCAST   = 0xffff
	WM_SETTINGCHANGE = 0x001A
	SMTO_ABORTIFHUNG = 0x2
)

// SEE: https://support.microsoft.com/en-us/help/104011/how-to-propagate-environment-variables-to-the-system
// and https://msdn.microsoft.com/en-us/library/windows/desktop/ms682653(v=vs.85).aspx says:
// To programmatically add or modify system environment variables, add them to the
// KEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment registry key,
// then broadcast a WM_SETTINGCHANGE message with lParam set to the string "Environment".

func setWinEnvProxy(value string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.SET_VALUE)
	if err != nil {
		log.Printf("%v\n", k)
		log.Fatal(err)
	}
	defer k.Close()

	if value == "" {
		fmt.Println("Removing http_proxy environment variable")
		err = k.DeleteValue("http_proxy")
	} else {
		fmt.Printf("Setting http_proxy environment variable = %s\n", value)
		err = k.SetStringValue("http_proxy", value)
	}
	if err != nil {
		fmt.Println("SetProxyEnvVar ERROR!!!")
	}

	// notify windows-friendly programs that the environment variable has changed
	// note that not all programs listen for these changes, so some may need to be restarted
	var proc = syscall.NewLazyDLL("user32.dll").NewProc("SendMessageTimeoutW")
	//et, _, err :=
	envUTF := uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(envText)))
	proc.Call(HWND_BROADCAST, uintptr(WM_SETTINGCHANGE), 0, envUTF, uintptr(SMTO_ABORTIFHUNG), uintptr(5000))
	//todo:  reimplement check, ignore errors which are actually success messages
	// if err != nil {
	// 	fmt.Printf("UpdateEnvPath ERROR!!! %v %v ??!\n", ret, err)
	// 	log.Fatal(err)
	// }
}
