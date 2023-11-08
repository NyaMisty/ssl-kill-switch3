//
//  SSLKillSwitch.m
//  SSLKillSwitch
//
//  Created by Alban Diquet on 7/10/15.
//  Copyright (c) 2015 Alban Diquet. All rights reserved.
//

// avoid deprecation warnings like kSSLSessionOptionBreakOnServerAuth
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wunused-variable"

#import <Foundation/Foundation.h>
#import <Security/SecureTransport.h>

#import <dlfcn.h>
#import <objc/runtime.h>

#import <rootless.h>

#if SUBSTRATE_BUILD
#import "substrate.h"

#define PREFERENCE_FILE ROOT_PATH_NS("/var/mobile/Library/Preferences/com.nablac0d3.SSLKillSwitchSettings.plist")
#define PREFERENCE_KEY @"shouldDisableCertificateValidation"

#else // SUBSTRATE_BUILD

#import "fishhook.h"

#endif // SUBSTRATE_BUILD


#pragma mark Utility Functions

#define SSKLOGLEVEL_VERBOSE     10
#define SSKLOGLEVEL_INFO        6
#define SSKLOGLEVEL_WARNING     4
#define SSKLOGLEVEL_DISABLED    1

int g_logLevel = SSKLOGLEVEL_VERBOSE; // for situations like Non-Substrate

#ifndef USE_NSLOG

// we use os_log instead, because we actually don't want to pollute the stderr
#import <os/log.h>
#define _SSKLog(format, ...) os_log(OS_LOG_DEFAULT, "=== SSL Kill Switch 3: " format, ##__VA_ARGS__)
// static void __SSKLog(NSString *format, ...)
// {
//     va_list args;
//     va_start(args, format);
//     NSString *newFormat = [[NSString alloc] initWithFormat:@"=== SSL Kill Switch 3: %{public}@", format];
//     NSString *formatted = [[NSString alloc] initWithFormat:newFormat arguments:args];
//     os_log(OS_LOG_DEFAULT, "%{public}@", formatted);
//     va_end(args);
// }
// #define _SSKLog(format, ...) __SSKLog(@format, ##__VA_ARGS__)

#else // USE_NSLOG

static void __SSKLog(NSString *format, ...)
{
    NSString *newFormat = [[NSString alloc] initWithFormat:@"=== SSL Kill Switch 3: %{public}@", format];
    va_list args;
    va_start(args, format);
    NSLogv(newFormat, args);
    va_end(args);
}
#define _SSKLog(format, ...) __SSKLog(@format, ##__VA_ARGS__)

#endif// USE_NSLOG

#define SSKVerboseLog(format, ...) { if (g_logLevel >= SSKLOGLEVEL_VERBOSE) _SSKLog("[verb] " format, ##__VA_ARGS__); }
#define SSKInfoLog(format, ...) { if (g_logLevel >= SSKLOGLEVEL_INFO) _SSKLog("[info] " format, ##__VA_ARGS__); }
#define SSKWarningLog(format, ...) { if (g_logLevel >= SSKLOGLEVEL_WARNING) _SSKLog("[warn] " format, ##__VA_ARGS__); }

#define HOOKBODY(body) {SSKVerboseLog(" >> Entering %{public}s()", __func__); body; SSKVerboseLog(" << Leaving %{public}s()", __func__);}

#define UNUSED(var) ((void)(var));

// Utility function to read the Tweak's preferences
static BOOL shouldHookFromPreference()
{
#if SUBSTRATE_BUILD
    NSString *preferenceSetting = PREFERENCE_KEY;
    BOOL shouldHook = NO;
    NSMutableDictionary* plist = [[NSMutableDictionary alloc] initWithContentsOfFile:PREFERENCE_FILE];

    if (!plist)
    {
        SSKWarningLog("Preference file %{public}@ not found.", PREFERENCE_FILE);
    }
    else
    {
        g_logLevel = [[plist objectForKey:@"logLevel"] integerValue];
        if (!g_logLevel) {
            SSKWarningLog("LogLevel is wrong (set to zero), we will output everything!");
            g_logLevel = SSKLOGLEVEL_VERBOSE;
        }
        SSKInfoLog("Using LogLevel = %d", g_logLevel);

        shouldHook = [[plist objectForKey:@"shouldDisableCertificateValidation"] boolValue];
        SSKInfoLog("Preference set to %d.", shouldHook);

        // Checking if BundleId has been excluded by user
        NSString *bundleId = [[NSBundle mainBundle] bundleIdentifier];
        bundleId = [bundleId stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

        NSString *excludedBundleIdsString = [plist objectForKey:@"excludedBundleIds"];
        excludedBundleIdsString = [excludedBundleIdsString stringByReplacingOccurrencesOfString:@" " withString:@""];

        NSArray *excludedBundleIds = [excludedBundleIdsString componentsSeparatedByString:@","];

        if ([excludedBundleIds containsObject:bundleId])
        {
            SSKInfoLog("Not hooking excluded bundle: %{public}@", bundleId);
            shouldHook = NO;
        }
    }
    return shouldHook;
#else
    // Always hook when using fishhook (for iOS jailed / macOS)
    return YES;
#endif
}



#pragma mark SecureTransport hooks - iOS 9 and below
// Explanation here: https://nabla-c0d3.github.io/blog/2013/08/20/ios-ssl-kill-switch-v0-dot-5-released/

static OSStatus (*original_SSLSetSessionOption)(SSLContextRef context,
                                                SSLSessionOption option,
                                                Boolean value);

static OSStatus replaced_SSLSetSessionOption(SSLContextRef context,
                                             SSLSessionOption option,
                                             Boolean value)
HOOKBODY({
    // Remove the ability to modify the value of the kSSLSessionOptionBreakOnServerAuth option
    if (option == kSSLSessionOptionBreakOnServerAuth)
    {
        return noErr;
    }
    return original_SSLSetSessionOption(context, option, value);
})


static SSLContextRef (*original_SSLCreateContext)(CFAllocatorRef alloc,
                                                  SSLProtocolSide protocolSide,
                                                  SSLConnectionType connectionType);

static SSLContextRef replaced_SSLCreateContext(CFAllocatorRef alloc,
                                               SSLProtocolSide protocolSide,
                                               SSLConnectionType connectionType)
HOOKBODY({
    SSLContextRef sslContext = original_SSLCreateContext(alloc, protocolSide, connectionType);

    // Immediately set the kSSLSessionOptionBreakOnServerAuth option in order to disable cert validation
    original_SSLSetSessionOption(sslContext, kSSLSessionOptionBreakOnServerAuth, true);
    return sslContext;
})


static OSStatus (*original_SSLHandshake)(SSLContextRef context);

static OSStatus replaced_SSLHandshake(SSLContextRef context)
HOOKBODY({

    OSStatus result = original_SSLHandshake(context);

    // Hijack the flow when breaking on server authentication
    if (result == errSSLServerAuthCompleted)
    {
        // Do not check the cert and call SSLHandshake() again
        return original_SSLHandshake(context);
    }

    return result;
})


#pragma mark libsystem_coretls.dylib hooks - iOS 10
// Explanation here: https://nabla-c0d3.github.io/blog/2017/02/05/ios10-ssl-kill-switch/

static OSStatus (*original_tls_helper_create_peer_trust)(void *hdsk, bool server, SecTrustRef *trustRef);

static OSStatus replaced_tls_helper_create_peer_trust(void *hdsk, bool server, SecTrustRef *trustRef)
HOOKBODY({
    // Do not actually set the trustRef
    return errSecSuccess;
})


#pragma mark BoringSSL hooks - iOS 12
// Explanation here: https://nabla-c0d3.github.io/blog/2019/05/18/ssl-kill-switch-for-ios12/

// Everyone's favorite OpenSSL constant
#define SSL_VERIFY_NONE 0

// Constant defined in BoringSSL
enum ssl_verify_result_t {
    ssl_verify_ok = 0,
    ssl_verify_invalid,
    ssl_verify_retry,
};


char *replaced_SSL_get_psk_identity(void *ssl)
HOOKBODY({
    return "notarealPSKidentity";
})


static int custom_verify_callback_that_does_not_validate(void *ssl, uint8_t *out_alert)
HOOKBODY({
    // Yes this certificate is 100% valid...
    return ssl_verify_ok;
})


static void (*original_SSL_CTX_set_custom_verify)(void *ctx, int mode, int (*callback)(void *ssl, uint8_t *out_alert));
static void replaced_SSL_CTX_set_custom_verify(void *ctx, int mode, int (*callback)(void *ssl, uint8_t *out_alert))
HOOKBODY({
    original_SSL_CTX_set_custom_verify(ctx, SSL_VERIFY_NONE, custom_verify_callback_that_does_not_validate);
    return;
})


static void (*original_SSL_set_custom_verify)(void *ssl, int mode, int (*callback)(void *ssl, uint8_t *out_alert));
static void replaced_SSL_set_custom_verify(void *ssl, int mode, int (*callback)(void *ssl, uint8_t *out_alert))
HOOKBODY({
    original_SSL_set_custom_verify(ssl, SSL_VERIFY_NONE, custom_verify_callback_that_does_not_validate);
    return;
})


#pragma mark CocoaSPDY hook

static void (*oldSetTLSTrustEvaluator)(id self, SEL _cmd, id evaluator);

static void newSetTLSTrustEvaluator(id self, SEL _cmd, id evaluator)
HOOKBODY({
    // Set a nil evaluator to disable SSL validation
    oldSetTLSTrustEvaluator(self, _cmd, nil);
})

static void (*oldSetprotocolClasses)(id self, SEL _cmd, NSArray <Class> *protocolClasses);

static void newSetprotocolClasses(id self, SEL _cmd, NSArray <Class> *protocolClasses)
HOOKBODY({
    // Do not register protocol classes which is how CocoaSPDY works
    // This should force the App to downgrade from SPDY to HTTPS
})

static void (*oldRegisterOrigin)(id self, SEL _cmd, NSString *origin);

static void newRegisterOrigin(id self, SEL _cmd, NSString *origin)
HOOKBODY({
    // Do not register protocol classes which is how CocoaSPDY works
    // This should force the App to downgrade from SPDY to HTTPS
})

#pragma mark SecPolicyCreateAppleSSLPinned hook
// adapted from https://github.com/sskaje/ssl-kill-switch2/commit/92a4222a4db7b16179b5a3045e1647ce13532c75
// use with AppleServerAuthenticationNoPinning in https://vtky.github.io/2021/01/05/apple-globalpreferences

static bool (*original_SecIsInternalRelease)(void);
static bool replace_SecIsInternalRelease(void) 
HOOKBODY({
    SSKVerboseLog("replace_SecIsInternalRelease: void");
    static bool isInternal = true;
    return isInternal;
})

#pragma mark SecTrustEvaluate API hook
// adapted from https://github.com/doug-leith/cydia/blob/7b14460d01224526a440267f3735b079bf0ab4eb/unpin/Tweak.m

static OSStatus (*original_SecTrustEvaluate)(SecTrustRef trust, SecTrustResultType *result);
static OSStatus replaced_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) 
HOOKBODY({
    OSStatus res = original_SecTrustEvaluate(trust, result);
    UNUSED (res);
    if (result) {
        SSKVerboseLog("Overrided SecTrustEvaluate() = %d, original result %d -> kSecTrustResultUnspecified(4)", res, *result);
        // Actually, this certificate chain is trusted
        *result = kSecTrustResultUnspecified;
    }
    return 0; // errSecSuccess
})

static bool (*original_SecTrustEvaluateWithError)(SecTrustRef trust, CFErrorRef *error);
static bool replaced_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) 
HOOKBODY({
    bool res = original_SecTrustEvaluateWithError(trust, error);
    UNUSED (res);
    if (error) {
        if (*error) {
            SSKVerboseLog("Overrided SecTrustEvaluateWithError() = %d, original err %{public}@", (int)res, *error);
            *error = nil;
        }
    }
    return true; // true means trusted
})

static OSStatus (*original_SecTrustEvaluateAsync)(SecTrustRef trust, dispatch_queue_t queue, SecTrustCallback result);
static OSStatus replaced_SecTrustEvaluateAsync(SecTrustRef trust, dispatch_queue_t queue, SecTrustCallback result)
HOOKBODY({
    dispatch_async(queue, ^{
        SSKVerboseLog("Overrided SecTrustEvaluateAsync!");
        result(
            trust,      // SecTrustRef trust
            1           // bool result
        );  // call the callback with success result
    });
	return 0; // errSecSuccess
})

static OSStatus (*original_SecTrustEvaluateAsyncWithError)(SecTrustRef trust, dispatch_queue_t queue, SecTrustWithErrorCallback result);
static OSStatus replaced_SecTrustEvaluateAsyncWithError(SecTrustRef trust, dispatch_queue_t queue, SecTrustWithErrorCallback result)
HOOKBODY({
    dispatch_async(queue, ^{
        SSKVerboseLog("Overrided SecTrustEvaluateAsyncWithError!");
        result(
            trust,      // SecTrustRef trust
            1,          // bool result
            NULL        // CFErrorRef error (nullable)
        );  // call the callback with success result
    });
	return 0; // errSecSuccess
})

static OSStatus (*original_SecTrustEvaluateFastAsync)(SecTrustRef trust, dispatch_queue_t queue, SecTrustCallback result);
static OSStatus replaced_SecTrustEvaluateFastAsync(SecTrustRef trust, dispatch_queue_t queue, SecTrustCallback result)
HOOKBODY({
    dispatch_async(queue, ^{
        SSKVerboseLog("Overrided SecTrustEvaluateFastAsync!");
        result(
            trust,      // SecTrustRef trust
            1           // bool result
        );  // call the callback with success result
    });
	return 0; // errSecSuccess
})

static OSStatus (*original_SecTrustSetPolicies)(SecTrustRef trust, void* policies);
static OSStatus replaced_SecTrustSetPolicies(SecTrustRef trust, void* policies)
HOOKBODY({
    SSKVerboseLog("Overrided SecTrustSetPolicies!");
    return 0; // errSecSuccess
})

#pragma mark Manual Pinning ([NSURLSessionDelegate URLSession:didReceiveChallenge:completionHandler:])
// https://developer.apple.com/documentation/foundation/nsurlauthenticationmethodservertrust
// URLSession:didReceiveChallenge:completionHandler: are triggered in CFNetwork from 4 places:
//   -[__NSCFLocalSessionTask _onqueue_didReceiveChallenge:request:withCompletion:] - easy to patch, usually triggers
//   -[__NSCFTCPIOStreamTask _onqueue_sendSessionChallenge:completionHandler:] - easy to patch, hardly triggers
//   -[__NSURLBackgroundSession backgroundTask:didReceiveChallenge:reply:] - hard to patch (have some password auth setup inside), hardly triggers
//   unknown - cannot analysis due to missing xref

void checkChallengeAndOverride(id challenge, void (^completion)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential)) {
	BOOL needOverrideCompletion = NO;

	NSURLProtectionSpace *protectionSpace = [challenge protectionSpace];
	if ([@"https" isEqualToString:[protectionSpace protocol]]) {
		needOverrideCompletion = YES;
	}
	if (needOverrideCompletion) {
		dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0),  ^{
			completion(NSURLSessionAuthChallengeUseCredential, [[NSURLCredential alloc] initWithTrust:[protectionSpace serverTrust]]);
		});
	}
}

static void (*old__NSCFLocalSessionTask__onqueue_didReceiveChallenge)(id self, SEL _cmd, id challenge, id request, void (^completion)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential) );
static void new__NSCFLocalSessionTask__onqueue_didReceiveChallenge(id self, SEL _cmd, id challenge, id request, void (^completion)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential) ) 
HOOKBODY({
	SSKVerboseLog("__NSCFLocalSessionTask _onqueue_didReceiveChallenge! protectionSpace: %{public}@", [challenge protectionSpace]);
	checkChallengeAndOverride(challenge, completion);
	// return %orig(challenge, req, completion);
})

static BOOL (*old__NSCFTCPIOStreamTask__onqueue_sendSessionChallenge)(id self, SEL _cmd, id challenge, void (^completion)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential) );
static BOOL new__NSCFTCPIOStreamTask__onqueue_sendSessionChallenge(id self, SEL _cmd, id challenge, void (^completion)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential) ) 
HOOKBODY({
	SSKVerboseLog("__NSCFTCPIOStreamTask _onqueue_sendSessionChallenge! protectionSpace: %{public}@", [challenge protectionSpace]);
	checkChallengeAndOverride(challenge, completion);
	return YES;
	// return %orig;
})

#pragma mark AFNetworking
static BOOL (*old__AFSecurityPolicy_setSSLPinningMode)(id self, SEL _cmd, uintptr_t mode);
static BOOL new__AFSecurityPolicy_setSSLPinningMode(id self, SEL _cmd, int mode) 
HOOKBODY({
    SSKVerboseLog("AFSecurityPolicy setSSLPinningMode: %d -> 0", mode);
    return old__AFSecurityPolicy_setSSLPinningMode(self, _cmd, 0); // AFSSLPinningModeNone
})

static BOOL (*old__AFSecurityPolicy_setAllowInvalidCertificates)(id self, SEL _cmd, BOOL allow);
static BOOL new__AFSecurityPolicy_setAllowInvalidCertificates(id self, SEL _cmd, BOOL allow) 
HOOKBODY({
    SSKVerboseLog("AFSecurityPolicy setAllowInvalidCertificates: %d -> YES", allow);
    return old__AFSecurityPolicy_setAllowInvalidCertificates(self, _cmd, YES);
})

static BOOL (*old__AFSecurityPolicy_policyWithPinningMode)(id cls, SEL _cmd, BOOL mode);
static BOOL new__AFSecurityPolicy_policyWithPinningMode(id cls, SEL _cmd, BOOL mode) 
HOOKBODY({
    SSKVerboseLog("AFSecurityPolicy policyWithPinningMode: %d -> AFSSLPinningModeNone", mode);
    return old__AFSecurityPolicy_setAllowInvalidCertificates(cls, _cmd, 0); // AFSSLPinningModeNone
})

static BOOL (*old__AFSecurityPolicy_policyWithPinningMode_withPinnedCertificates)(id cls, SEL _cmd, BOOL mode, id cert);
static BOOL new__AFSecurityPolicy_policyWithPinningMode_withPinnedCertificates(id cls, SEL _cmd, BOOL mode, id cert) 
HOOKBODY({
    SSKVerboseLog("AFSecurityPolicy policyWithPinningMode: %d withPinnedCertificates: %{public}@ -> AFSSLPinningModeNone", mode, cert);
    return old__AFSecurityPolicy_policyWithPinningMode_withPinnedCertificates(cls, _cmd, 0, cert); // AFSSLPinningModeNone
})

#pragma mark TrustKit - TSKPinningValidator

// "- evaluateTrust:forHostname:"
static int (*old__TSKPinningValidator_evaluateTrust_forHostname)(id self, SEL _cmd, id trust, id hostname);
static int new__TSKPinningValidator_evaluateTrust_forHostname(id self, SEL _cmd, id trust, id hostname) 
HOOKBODY({
    int ret = old__TSKPinningValidator_evaluateTrust_forHostname(self, _cmd, trust, hostname); // AFSSLPinningModeNone
    SSKVerboseLog("TSKPinningValidator evaluateTrust: %{public}@ forHostname: %{public}@ ret: %d -> 0", trust, hostname, ret);
    return 0; // pass
})

#pragma mark cordova - CustomURLConnectionDelegate
// "- isFingerprintTrusted:"
static int (*old__CustomURLConnectionDelegate_isFingerprintTrusted)(id self, SEL _cmd, id fingerprint);
static int new__CustomURLConnectionDelegate_isFingerprintTrusted(id self, SEL _cmd, id fingerprint) 
HOOKBODY({
    int ret = old__CustomURLConnectionDelegate_isFingerprintTrusted(self, _cmd, fingerprint); // AFSSLPinningModeNone
    SSKVerboseLog("CustomURLConnectionDelegate isFingerprintTrusted: %{public}@ ret: %d -> 0", fingerprint, ret);
    return 0; // pass
})

#pragma mark Dylib Constructor

#include <ptrauth.h>

static uint64_t parse_branch_instruction(uint32_t instruction, uint64_t pc) {
    // parse B instruction
    uint32_t opcode = (instruction >> 26) & 0x3F;
    printf("%x\n", opcode);
    uint32_t imm26 = instruction & 0x03FFFFFF;

    // check if it's B instruction（opcode == 0b100101）
    if (opcode != 0b000101) {
        return 0;
    }

    // calc target address
    uint32_t sign_bit = imm26 >> 25;
    uint64_t offset = (imm26 << 2) & 0x1FFFFFF;
    uint64_t target_address = pc + offset;

    // handle imm26 sign bit
    if (sign_bit) {
        target_address -= (1 << 25);
    }

    return target_address;
}

void hookF(const char *libName, const char *funcName, void *replaceFun, void **origFun) {
    SSKVerboseLog("[init] hookF('%{public}s', '%{public}s', %p, %p);", libName ? libName:"(null)", funcName, replaceFun, origFun);

    void *libHandle = RTLD_DEFAULT;
    if (libName) {
        libHandle = dlopen(libName, RTLD_NOW);
        if (!libHandle) {
            libHandle = RTLD_DEFAULT;
        }
    }
    void *pFunc = dlsym(libHandle, funcName);
    if (!pFunc) {
        SSKInfoLog("[init] hookF failed to find function %{public}s", funcName);
        return;
    }
    uint32_t *pIns = (uint32_t *)ptrauth_strip(pFunc, ptrauth_key_function_pointer);
    SSKVerboseLog("[init] hookF resolved pFunc -> %p -> %p", pFunc, pIns);

#if SUBSTRATE_BUILD
        void *originalMem[3] = {0};
        memcpy(originalMem, pIns, sizeof(originalMem));
        uintptr_t targetAddr = parse_branch_instruction(pIns[0], (uint64_t)pIns);
        if (targetAddr) {
            SSKInfoLog("%{public}s jumps to %p: %llx, hook new addr instead!", funcName, targetAddr, *(void **)targetAddr);
            pFunc = (void *)targetAddr;
        }
        MSHookFunction(pFunc, replaceFun, origFun);

        void *newMem[3] = {0};
        memcpy(newMem, pIns, sizeof(newMem));
        SSKVerboseLog("[init] hookF result: func %{public}s ptr %p, from %p %p %p to %p %p %p", 
            funcName, pIns, 
            originalMem[0], originalMem[1], originalMem[2],
            newMem[0], newMem[1], newMem[2]);
#else
        if (origFun)
            *origFun = pFunc;
        if (rebind_symbols((struct rebinding[1]){{(char *)funcName, (void *)replaceFun}}, 1) < 0) {
            SSKInfoLog("Failed to do fish hook for %{public}s!", funcName);
        }
#endif
}

BOOL hookM(Class _class, SEL _cmd, IMP _new, IMP *_old) {
    SSKVerboseLog("[init] hookM(%p, '%{public}@', %p, %p);", _class, NSStringFromSelector(_cmd), _new, _old);
    if (!_class) {
        return NO;
    }
#if SUBSTRATE_BUILD
    MSHookMessageEx(_class, _cmd, _new, _old);
    return YES;
#else
    // From: static void _logos_register_hook(Class _class, SEL _cmd, IMP _new, IMP* _old)
    unsigned int _count, _i;
    Class _searchedClass = _class;
    Method* _methods;
    while (_searchedClass) {
        _methods = class_copyMethodList(_searchedClass, &_count);
        for (_i = 0; _i < _count; _i++) {
            if (method_getName(_methods[_i]) == _cmd) {
                if (_class == _searchedClass) {
                    *_old = method_getImplementation(_methods[_i]);
                    *_old = method_setImplementation(_methods[_i], _new);
                } else {
                    class_addMethod(_class, _cmd, _new,
                                    method_getTypeEncoding(_methods[_i]));
                }
                free(_methods);
                return YES;
            }
        }
        free(_methods);
        _searchedClass = class_getSuperclass(_searchedClass);
    }
    return NO;
#endif
}

__attribute__((constructor)) static void init(int argc, const char **argv)
{
    // Only hook if the preference file says so
    if (shouldHookFromPreference())
    {
        SSKInfoLog("Hook enabled.");

        NSProcessInfo *processInfo = [NSProcessInfo processInfo];
        if ([processInfo isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){12, 0, 0}])
        {
            // Support for iOS 12 and 13

            if ([processInfo isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){13, 0, 0}])
            {
                SSKInfoLog("iOS 13+ detected");
                // iOS 13 uses SSL_set_custom_verify() which was recently added to BoringSSL
                hookF("/usr/lib/libboringssl.dylib", "SSL_set_custom_verify", (void *) replaced_SSL_set_custom_verify,  (void **) &original_SSL_set_custom_verify);
            }
            else
            {
                SSKInfoLog("iOS 12 detected");
                // iOS 12 uses the older SSL_CTX_set_custom_verify()
                hookF("/usr/lib/libboringssl.dylib", "SSL_CTX_set_custom_verify", (void *) replaced_SSL_CTX_set_custom_verify,  (void **) &original_SSL_CTX_set_custom_verify);
            }
            
            // Hook SSL_get_psk_identity() on both iOS 12 and 13
            hookF("/usr/lib/libboringssl.dylib", "SSL_get_psk_identity", (void *) replaced_SSL_get_psk_identity,  (void **) NULL);
        }
		else if ([processInfo isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){11, 0, 0}])
		{
            // Support for iOS 11
            SSKInfoLog("iOS 11 detected; hooking nw_tls_create_peer_trust()...");
			hookF("/usr/lib/libnetwork.dylib", "nw_tls_create_peer_trust", (void *) replaced_tls_helper_create_peer_trust,  (void **) &original_tls_helper_create_peer_trust);
		}
        else if ([processInfo isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){10, 0, 0}])
        {
            // Support for iOS 10
            SSKInfoLog("iOS 10 detected; hooking tls_helper_create_peer_trust()...");
            hookF(NULL, "tls_helper_create_peer_trust", (void *) replaced_tls_helper_create_peer_trust,  (void **) &original_tls_helper_create_peer_trust);
        }
        else if ([processInfo isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){8, 0, 0}])
        {
            // SecureTransport hooks - works up to iOS 9
            SSKInfoLog("iOS 8 or 9 detected; hooking SecureTransport...");
            hookF(NULL, "SSLHandshake",(void *)  replaced_SSLHandshake, (void **) &original_SSLHandshake);
            hookF(NULL, "SSLSetSessionOption",(void *)  replaced_SSLSetSessionOption, (void **) &original_SSLSetSessionOption);
            hookF(NULL, "SSLCreateContext",(void *)  replaced_SSLCreateContext, (void **) &original_SSLCreateContext);
        }

        // CocoaSPDY hooks - https://github.com/twitter/CocoaSPDY
        // TODO: Enable these hooks for the fishhook-based hooking so it works on OS X too
        Class spdyProtocolClass = NSClassFromString(@"SPDYProtocol");
        if (spdyProtocolClass)
        {
            SSKInfoLog("CocoaSPDY detected; hooking it...");
            // Disable trust evaluation
            hookM(object_getClass(spdyProtocolClass), NSSelectorFromString(@"setTLSTrustEvaluator:"), (IMP) &newSetTLSTrustEvaluator, (IMP *)&oldSetTLSTrustEvaluator);

            // CocoaSPDY works by getting registered as a NSURLProtocol; block that so the Apps switches back to HTTP as SPDY is tricky to proxy
            Class spdyUrlConnectionProtocolClass = NSClassFromString(@"SPDYURLConnectionProtocol");
            hookM(object_getClass(spdyUrlConnectionProtocolClass), NSSelectorFromString(@"registerOrigin:"), (IMP) &newRegisterOrigin, (IMP *)&oldRegisterOrigin);

            hookM(NSClassFromString(@"NSURLSessionConfiguration"), NSSelectorFromString(@"setprotocolClasses:"), (IMP) &newSetprotocolClasses, (IMP *)&oldSetprotocolClasses);
        }

        SSKInfoLog("Hooking Security framework...");
        // Security framework hook 1
        hookF(NULL, "SecIsInternalRelease", (void *) replace_SecIsInternalRelease,  (void **) &original_SecIsInternalRelease);
        
        // SecTrustEvaluate iOS 2-13
        // SecTrustEvaluateAsync iOS 7-13
        hookF(NULL, "SecTrustEvaluate",(void *)  replaced_SecTrustEvaluate, (void **) &original_SecTrustEvaluate);
        hookF(NULL, "SecTrustEvaluateAsync",(void *)  replaced_SecTrustEvaluateAsync, (void **) &original_SecTrustEvaluateAsync);
        // SecTrustEvaluateWithError iOS 12-
        // SecTrustEvaluateAsyncWithError iOS 13-
        // SecTrustEvaluateFastAsync iOS 12-
        hookF(NULL, "SecTrustEvaluateWithError",(void *)  replaced_SecTrustEvaluateWithError, (void **) &original_SecTrustEvaluateWithError);
        hookF(NULL, "SecTrustEvaluateAsyncWithError",(void *)  replaced_SecTrustEvaluateAsyncWithError, (void **) &original_SecTrustEvaluateAsyncWithError);
        hookF(NULL, "SecTrustEvaluateFastAsync",(void *)  replaced_SecTrustEvaluateFastAsync, (void **) &original_SecTrustEvaluateFastAsync);
        // SecTrustEvaluateWithError iOS 6-
        hookF(NULL, "SecTrustSetPolicies",(void *)  replaced_SecTrustSetPolicies, (void **) &original_SecTrustSetPolicies);

        SSKInfoLog("Hooking URLSession...");
        // hook URLSession:didReceiveChallenge:completionHandler:
        if (!hookM(NSClassFromString(@"__NSCFLocalSessionTask"), NSSelectorFromString(@"_onqueue_didReceiveChallenge:request:withCompletion:"), (IMP) &new__NSCFLocalSessionTask__onqueue_didReceiveChallenge, (IMP *)&old__NSCFLocalSessionTask__onqueue_didReceiveChallenge)) {
            SSKInfoLog("Cannot find [__NSCFLocalSessionTask _onqueue_didReceiveChallenge:request:withCompletion:]");
        }
        if (!hookM(NSClassFromString(@"__NSCFTCPIOStreamTask"), NSSelectorFromString(@"_onqueue_sendSessionChallenge:completionHandler:"), (IMP) &new__NSCFTCPIOStreamTask__onqueue_sendSessionChallenge, (IMP *)&old__NSCFTCPIOStreamTask__onqueue_sendSessionChallenge)) {
            SSKInfoLog("Cannot find [__NSCFTCPIOStreamTask _onqueue_sendSessionChallenge:completionHandler:]");
        }

        // AFNetworking hook: https://github.com/sensepost/objection/blob/6c55d7e46292048d629dbe361701e5fe3e02d8d0/agent/src/ios/pinning.ts#L48
        Class afSecurifyPolicyClass = NSClassFromString(@"AFSecurityPolicy");
        if (afSecurifyPolicyClass)
        {
            SSKInfoLog("AFNetworking detected; hooking it...");
            // - setSSLPinningMode: & - setAllowInvalidCertificates:
            hookM(afSecurifyPolicyClass, NSSelectorFromString(@"setSSLPinningMode:"), (IMP) &new__AFSecurityPolicy_setSSLPinningMode, (IMP *)&old__AFSecurityPolicy_setSSLPinningMode);
            hookM(afSecurifyPolicyClass, NSSelectorFromString(@"setAllowInvalidCertificates:"), (IMP) &new__AFSecurityPolicy_setAllowInvalidCertificates, (IMP *)&old__AFSecurityPolicy_setAllowInvalidCertificates);
            // + policyWithPinningMode: & + policyWithPinningMode:withPinnedCertificates:
            hookM(object_getClass(afSecurifyPolicyClass), NSSelectorFromString(@"policyWithPinningMode:"), (IMP) &new__AFSecurityPolicy_policyWithPinningMode, (IMP *)&old__AFSecurityPolicy_policyWithPinningMode);
            hookM(object_getClass(afSecurifyPolicyClass), NSSelectorFromString(@"policyWithPinningMode:withPinnedCertificates:"), (IMP) &new__AFSecurityPolicy_policyWithPinningMode_withPinnedCertificates, (IMP *)&old__AFSecurityPolicy_policyWithPinningMode_withPinnedCertificates);
        }
        // TrustKit TSKPinningValidator hook: https://github.com/sensepost/objection/blob/6c55d7e46292048d629dbe361701e5fe3e02d8d0/agent/src/ios/pinning.ts#L254
        Class tskPinningValidatorClass = NSClassFromString(@"TSKPinningValidator");
        if (tskPinningValidatorClass)
        {
            SSKInfoLog("TrustKit TSKPinningValidator detected; hooking it...");
            // - evaluateTrust:forHostname:
            hookM(tskPinningValidatorClass, NSSelectorFromString(@"evaluateTrust:forHostname:"), (IMP) &new__TSKPinningValidator_evaluateTrust_forHostname, (IMP *)&old__TSKPinningValidator_evaluateTrust_forHostname);
        }
        // SSLCertificateChecker-PhoneGap-Plugin CustomURLConnectionDelegate hook: https://github.com/sensepost/objection/blob/6c55d7e46292048d629dbe361701e5fe3e02d8d0/agent/src/ios/pinning.ts#L285
        Class customURLConnectionDelegateClass = NSClassFromString(@"CustomURLConnectionDelegate");
        if (customURLConnectionDelegateClass)
        {
            SSKInfoLog("SSLCertificateChecker-PhoneGap-Plugin CustomURLConnectionDelegate detected; hooking it...");
            // - isFingerprintTrusted:
            hookM(customURLConnectionDelegateClass, NSSelectorFromString(@"isFingerprintTrusted:"), (IMP) &new__CustomURLConnectionDelegate_isFingerprintTrusted, (IMP *)&old__CustomURLConnectionDelegate_isFingerprintTrusted);
        }

    }
    else
    {
        SSKInfoLog("Hook disabled.");
    }
}
