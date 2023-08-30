//go:build darwin

package main

/*
#cgo CFLAGS: -x objective-c -fmodules
#cgo LDFLAGS: -framework Foundation -framework SystemConfiguration
#import <Foundation/NSArray.h>
#import <Foundation/Foundation.h>
#import <SystemConfiguration/SCPreferences.h>
#import <SystemConfiguration/SCNetworkConfiguration.h>

#include <sys/syslimits.h>
#include <sys/stat.h>
#include <mach-o/dyld.h>

enum RET_ERRORS {
    RET_NO_ERROR = 0,
    INVALID_FORMAT = 1,
    NO_PERMISSION = 2,
    SYSCALL_FAILED = 3,
    NO_MEMORY = 4
};

typedef Boolean (*visitor) (SCNetworkProtocolRef proxyProtocolRef, NSDictionary* oldPreferences, NSDictionary* args);

Boolean showAction(SCNetworkProtocolRef proxyProtocolRef, NSDictionary* oldPreferences, NSDictionary* args)
{
    NSNumber* on = [oldPreferences valueForKey:(NSString*)kSCPropNetProxiesHTTPEnable];
    NSString* nsOldProxyHost = [oldPreferences valueForKey:(NSString*)kSCPropNetProxiesHTTPProxy];
    NSNumber* nsOldProxyPort = [oldPreferences valueForKey:(NSString*)kSCPropNetProxiesHTTPPort];
    if ([on intValue] == 1) {
        printf("%s:%d\n", [nsOldProxyHost UTF8String], [nsOldProxyPort intValue]);
    }

    return TRUE;
}

Boolean turnOnAction(SCNetworkProtocolRef proxyProtocolRef, NSDictionary* oldPreferences, NSDictionary* args) {
    NSString* nsProxyHost = [args objectForKey:@"host"];
    NSNumber* nsProxyPort = [args objectForKey:@"port"];

    NSMutableDictionary *newPreferences = [NSMutableDictionary dictionaryWithDictionary: oldPreferences];
    Boolean success;

    [newPreferences setValue: nsProxyHost forKey:(NSString*)kSCPropNetProxiesHTTPProxy];
    [newPreferences setValue: nsProxyHost forKey:(NSString*)kSCPropNetProxiesHTTPSProxy];
    [newPreferences setValue: nsProxyPort forKey:(NSString*)kSCPropNetProxiesHTTPPort];
    [newPreferences setValue: nsProxyPort forKey:(NSString*)kSCPropNetProxiesHTTPSPort];
    [newPreferences setValue:[NSNumber numberWithInt:1] forKey:(NSString*)kSCPropNetProxiesHTTPEnable];
    [newPreferences setValue:[NSNumber numberWithInt:1] forKey:(NSString*)kSCPropNetProxiesHTTPSEnable];

    success = SCNetworkProtocolSetConfiguration(proxyProtocolRef, (__bridge CFDictionaryRef)newPreferences);
    if(!success) {
        NSLog(@"Failed to set Protocol Configuration");
    }
    return success;
}

Boolean turnOffAction(SCNetworkProtocolRef proxyProtocolRef, NSDictionary* oldPreferences, NSDictionary* args) {
    NSMutableDictionary *newPreferences = [NSMutableDictionary dictionaryWithDictionary: oldPreferences];
    Boolean success;

    [newPreferences setValue:[NSNumber numberWithInt:0] forKey:(NSString*)kSCPropNetProxiesHTTPEnable];
    [newPreferences setValue: @"" forKey:(NSString*)kSCPropNetProxiesHTTPProxy];
    [newPreferences setValue: @"" forKey:(NSString*)kSCPropNetProxiesHTTPPort];
    [newPreferences setValue:[NSNumber numberWithInt:0] forKey:(NSString*)kSCPropNetProxiesHTTPSEnable];
    [newPreferences setValue: @"" forKey:(NSString*)kSCPropNetProxiesHTTPSProxy];
    [newPreferences setValue: @"" forKey:(NSString*)kSCPropNetProxiesHTTPSPort];

    success = SCNetworkProtocolSetConfiguration(proxyProtocolRef, (__bridge CFDictionaryRef)newPreferences);
    if(!success) {
        NSLog(@"Failed to set Protocol Configuration");
    }
    return success;
}

NSDictionary* visit(visitor v, bool persist, NSDictionary* args)
{
    NSMutableDictionary *ret = [NSMutableDictionary new];
    Boolean success;

    SCNetworkSetRef networkSetRef;
    CFArrayRef networkServicesArrayRef;
    SCNetworkServiceRef networkServiceRef;
    SCNetworkProtocolRef proxyProtocolRef;
    NSDictionary *oldPreferences;

    // Get System Preferences Lock
    SCPreferencesRef prefsRef = SCPreferencesCreate(NULL, CFSTR("org.getlantern.lantern"), NULL);

    if (prefsRef == NULL) {
        [ret setObject:@"Fail to obtain Preferences Ref" forKey:@"error"];
        [ret setObject:[[NSNumber alloc] initWithInt:NO_PERMISSION] forKey:@"code"];
        goto freePrefsRef;
    }

    success = SCPreferencesLock(prefsRef, true);
    if (!success) {
        [ret setObject:@"Fail to obtain PreferencesLock" forKey:@"error"];
        [ret setObject:[[NSNumber alloc] initWithInt:NO_PERMISSION] forKey:@"code"];
        goto freePrefsRef;
    }

    // Get available network services
    networkSetRef = SCNetworkSetCopyCurrent(prefsRef);
    if(networkSetRef == NULL) {
        [ret setObject:@"Fail to get available network services" forKey:@"error"];
        [ret setObject:[[NSNumber alloc] initWithInt:SYSCALL_FAILED] forKey:@"code"];
        goto freeNetworkSetRef;
    }

    //Look up interface entry
    networkServicesArrayRef = SCNetworkSetCopyServices(networkSetRef);
    networkServiceRef = NULL;
    for (long i = 0; i < CFArrayGetCount(networkServicesArrayRef); i++) {
        networkServiceRef = CFArrayGetValueAtIndex(networkServicesArrayRef, i);

        // Get proxy protocol
        proxyProtocolRef = SCNetworkServiceCopyProtocol(networkServiceRef, kSCNetworkProtocolTypeProxies);
        if(proxyProtocolRef == NULL) {
            [ret setObject:@"Couldn't acquire copy of proxyProtocol" forKey:@"error"];
            [ret setObject:[[NSNumber alloc] initWithInt:SYSCALL_FAILED] forKey:@"code"];
            goto freeProxyProtocolRef;
        }

        oldPreferences = (__bridge NSDictionary*)SCNetworkProtocolGetConfiguration(proxyProtocolRef);
        if (!v(proxyProtocolRef, oldPreferences, args)) {
            [ret setObject:[[NSNumber alloc] initWithInt:SYSCALL_FAILED] forKey:@"code"];
        }

        freeProxyProtocolRef:
        CFRelease(proxyProtocolRef);
    }

    if (persist) {
        success = SCPreferencesCommitChanges(prefsRef);
        if(!success) {
            [ret setObject:@"Failed to Commit Changes" forKey:@"error"];
            [ret setObject:[[NSNumber alloc] initWithInt:SYSCALL_FAILED] forKey:@"code"];
            goto freeNetworkServicesArrayRef;
        }

        success = SCPreferencesApplyChanges(prefsRef);
        if(!success) {
            [ret setObject:@"Failed to Apply Changes" forKey:@"error"];
            [ret setObject:[[NSNumber alloc] initWithInt:SYSCALL_FAILED] forKey:@"code"];
            goto freeNetworkServicesArrayRef;
        }
    }

    //Free Resources
    freeNetworkServicesArrayRef:
    CFRelease(networkServicesArrayRef);
    freeNetworkSetRef:
    CFRelease(networkSetRef);
    freePrefsRef:
    SCPreferencesUnlock(prefsRef);
    CFRelease(prefsRef);

    return ret;
}

const char* nsstring2cstring(NSString *s) {
    if (s == NULL) { return NULL; }

    const char *cstr = [s UTF8String];
    return cstr;
}

const char* dictionaryToString(NSDictionary *dict) {
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dict options:NSJSONWritingPrettyPrinted error:&error];
    NSString *data;
    if (! jsonData) {
        data = @"{}";
    } else {
        data = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    }

    return nsstring2cstring(data);
}

//int show(void)
//{
//    return visit(&showAction, false, @{});
//}


const char* turnOn(const char *host, const char *port)
{
    NSLog(@"%s:%s", host, port);
    NSString* nsProxyHost = [[NSString alloc] initWithCString: host encoding:NSUTF8StringEncoding];
    NSNumber* nsProxyPort = [[NSNumber alloc] initWithLong: [[[NSString alloc] initWithCString: port encoding:NSUTF8StringEncoding] integerValue]];

    NSLog(@"%@:%@", nsProxyHost, nsProxyPort);
    //NSDictionary* dict = @{
    //    @"host": @(nsProxyHost),
    //    @"port": @(nsProxyPort),
    //};
    NSMutableDictionary *args = [NSMutableDictionary new];
    [args setObject:nsProxyHost forKey:@"host"];
    [args setObject:nsProxyPort forKey:@"port"];

    return dictionaryToString(visit(&turnOnAction, true, args));
}

const char* turnOff() {
    return dictionaryToString(visit(&turnOffAction, true, @{}));
}
*/
import "C"

import (
	"encoding/json"
	"errors"
	"net"
	"unsafe"
)

type RequestResponse struct {
	Error string `json:"error,omitempty"`
	Code  uint   `json:"code,omitempty"`
}

func disableProxy() error {
	ret := C.turnOff()
	data := C.GoString(ret)

	var r RequestResponse
	if err := json.Unmarshal([]byte(data), &r); err != nil {
		return err
	}

	if r.Code != 0 {
		return errors.New(r.Error)
	}
	return nil
}

func enableProxy(addrPort string) error {
	host, port, err := net.SplitHostPort(addrPort)
	if err != nil {
		return err
	}

	chost := C.CString(host)
	cport := C.CString(port)

	ret := C.turnOn(chost, cport)
	C.free(unsafe.Pointer(chost))
	C.free(unsafe.Pointer(cport))

	data := C.GoString(ret)

	var r RequestResponse
	if err := json.Unmarshal([]byte(data), &r); err != nil {
		return err
	}

	if r.Code != 0 {
		return errors.New(r.Error)
	}
	return nil
}
