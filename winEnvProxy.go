package main

import (
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
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
