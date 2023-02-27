//
//  SSLKillSwitch.m
//  SSLKillSwitch
//
//  Created by Alban Diquet on 7/10/15.
//  Copyright (c) 2015 Alban Diquet. All rights reserved.
//

// avoid deprecation warnings like kSSLSessionOptionBreakOnServerAuth
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#import <Foundation/Foundation.h>
#import <Security/SecureTransport.h>

#import <dlfcn.h>
#import <objc/runtime.h>

#if SUBSTRATE_BUILD
#import "substrate.h"

#define PREFERENCE_FILE @"/private/var/mobile/Library/Preferences/com.nablac0d3.SSLKillSwitchSettings.plist"
#define PREFERENCE_KEY @"shouldDisableCertificateValidation"

#else // SUBSTRATE_BUILD

#import "fishhook.h"

#endif // SUBSTRATE_BUILD


#pragma mark Utility Functions

static void SSKLog(NSString *format, ...)
{
    NSString *newFormat = [[NSString alloc] initWithFormat:@"=== SSL Kill Switch 2: %@", format];
    va_list args;
    va_start(args, format);
    NSLogv(newFormat, args);
    va_end(args);
}


// Utility function to read the Tweak's preferences
static BOOL shouldHookFromPreference()
{
#if SUBSTRATE_BUILD
    NSString *preferenceSetting = PREFERENCE_KEY;
    BOOL shouldHook = NO;
    NSMutableDictionary* plist = [[NSMutableDictionary alloc] initWithContentsOfFile:PREFERENCE_FILE];

    if (!plist)
    {
        SSKLog(@"Preference file not found.");
    }
    else
    {
        shouldHook = [[plist objectForKey:preferenceSetting] boolValue];
        SSKLog(@"Preference set to %d.", shouldHook);

        // Checking if BundleId has been excluded by user
        NSString *bundleId = [[NSBundle mainBundle] bundleIdentifier];
        bundleId = [bundleId stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

        NSString *excludedBundleIdsString = [plist objectForKey:@"excludedBundleIds"];
        excludedBundleIdsString = [excludedBundleIdsString stringByReplacingOccurrencesOfString:@" " withString:@""];

        NSArray *excludedBundleIds = [excludedBundleIdsString componentsSeparatedByString:@","];

        if ([excludedBundleIds containsObject:bundleId])
        {
            SSKLog(@"Not hooking excluded bundle: %@", bundleId);
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
{
    // Remove the ability to modify the value of the kSSLSessionOptionBreakOnServerAuth option
    if (option == kSSLSessionOptionBreakOnServerAuth)
    {
        return noErr;
    }
    return original_SSLSetSessionOption(context, option, value);
}


static SSLContextRef (*original_SSLCreateContext)(CFAllocatorRef alloc,
                                                  SSLProtocolSide protocolSide,
                                                  SSLConnectionType connectionType);

static SSLContextRef replaced_SSLCreateContext(CFAllocatorRef alloc,
                                               SSLProtocolSide protocolSide,
                                               SSLConnectionType connectionType)
{
    SSLContextRef sslContext = original_SSLCreateContext(alloc, protocolSide, connectionType);

    // Immediately set the kSSLSessionOptionBreakOnServerAuth option in order to disable cert validation
    original_SSLSetSessionOption(sslContext, kSSLSessionOptionBreakOnServerAuth, true);
    return sslContext;
}


static OSStatus (*original_SSLHandshake)(SSLContextRef context);

static OSStatus replaced_SSLHandshake(SSLContextRef context)
{

    OSStatus result = original_SSLHandshake(context);

    // Hijack the flow when breaking on server authentication
    if (result == errSSLServerAuthCompleted)
    {
        // Do not check the cert and call SSLHandshake() again
        return original_SSLHandshake(context);
    }

    return result;
}


#pragma mark libsystem_coretls.dylib hooks - iOS 10
// Explanation here: https://nabla-c0d3.github.io/blog/2017/02/05/ios10-ssl-kill-switch/

static OSStatus (*original_tls_helper_create_peer_trust)(void *hdsk, bool server, SecTrustRef *trustRef);

static OSStatus replaced_tls_helper_create_peer_trust(void *hdsk, bool server, SecTrustRef *trustRef)
{
    // Do not actually set the trustRef
    return errSecSuccess;
}


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
{
    return "notarealPSKidentity";
}


static int custom_verify_callback_that_does_not_validate(void *ssl, uint8_t *out_alert)
{
    // Yes this certificate is 100% valid...
    return ssl_verify_ok;
}


static void (*original_SSL_CTX_set_custom_verify)(void *ctx, int mode, int (*callback)(void *ssl, uint8_t *out_alert));
static void replaced_SSL_CTX_set_custom_verify(void *ctx, int mode, int (*callback)(void *ssl, uint8_t *out_alert))
{
    SSKLog(@"Entering replaced_SSL_CTX_set_custom_verify()");
    original_SSL_CTX_set_custom_verify(ctx, SSL_VERIFY_NONE, custom_verify_callback_that_does_not_validate);
    return;
}


static void (*original_SSL_set_custom_verify)(void *ssl, int mode, int (*callback)(void *ssl, uint8_t *out_alert));
static void replaced_SSL_set_custom_verify(void *ssl, int mode, int (*callback)(void *ssl, uint8_t *out_alert))
{
    SSKLog(@"Entering replaced_SSL_set_custom_verify()");
    original_SSL_set_custom_verify(ssl, SSL_VERIFY_NONE, custom_verify_callback_that_does_not_validate);
    return;
}


#pragma mark CocoaSPDY hook

static void (*oldSetTLSTrustEvaluator)(id self, SEL _cmd, id evaluator);

static void newSetTLSTrustEvaluator(id self, SEL _cmd, id evaluator)
{
    // Set a nil evaluator to disable SSL validation
    oldSetTLSTrustEvaluator(self, _cmd, nil);
}

static void (*oldSetprotocolClasses)(id self, SEL _cmd, NSArray <Class> *protocolClasses);

static void newSetprotocolClasses(id self, SEL _cmd, NSArray <Class> *protocolClasses)
{
    // Do not register protocol classes which is how CocoaSPDY works
    // This should force the App to downgrade from SPDY to HTTPS
}

static void (*oldRegisterOrigin)(id self, SEL _cmd, NSString *origin);

static void newRegisterOrigin(id self, SEL _cmd, NSString *origin)
{
    // Do not register protocol classes which is how CocoaSPDY works
    // This should force the App to downgrade from SPDY to HTTPS
}

#pragma mark SecPolicyCreateAppleSSLPinned hook
// adapted from https://github.com/sskaje/ssl-kill-switch2/commit/92a4222a4db7b16179b5a3045e1647ce13532c75
// use with AppleServerAuthenticationNoPinning in https://vtky.github.io/2021/01/05/apple-globalpreferences

static bool (*original_SecIsInternalRelease)(void);
static bool replace_SecIsInternalRelease(void) {
    // SSKLog(@"replace_SecIsInternalRelease: void");
    static bool isInternal = true;
    return isInternal;
}

#pragma mark SecTrustEvaluate API hook
// adapted from https://github.com/doug-leith/cydia/blob/7b14460d01224526a440267f3735b079bf0ab4eb/unpin/Tweak.m

static OSStatus (*original_SecTrustEvaluate)(SecTrustRef trust, SecTrustResultType *result);
static OSStatus replaced_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    OSStatus res = original_SecTrustEvaluate(trust, result);
    #pragma unused (res)
    if (result) {
        SSKLog(@"Overrided SecTrustEvaluate() = %d, original result %d -> kSecTrustResultUnspecified(4)", res, *result);
        // Actually, this certificate chain is trusted
        *result = kSecTrustResultUnspecified;
    }
    return 0; // errSecSuccess
}

static bool (*original_SecTrustEvaluateWithError)(SecTrustRef trust, CFErrorRef *error);
static bool replaced_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    bool res = original_SecTrustEvaluateWithError(trust, error);
    #pragma unused (res)
    if (error) {
        if (*error) {
            SSKLog(@"Overrided SecTrustEvaluateWithError() = %d, original err %@", (int)res, *error);
            *error = nil;
        }
    }
    return true; // true means trusted
};

static OSStatus (*original_SecTrustEvaluateAsync)(SecTrustRef trust, dispatch_queue_t queue, SecTrustCallback result);
static OSStatus replaced_SecTrustEvaluateAsync(SecTrustRef trust, dispatch_queue_t queue, SecTrustCallback result){
    dispatch_async(queue, ^{
        SSKLog(@"Overrided SecTrustEvaluateAsync!");
        result(
            trust,      // SecTrustRef trust
            1           // bool result
        );  // call the callback with success result
    });
	return 0; // errSecSuccess
}

static OSStatus (*original_SecTrustEvaluateAsyncWithError)(SecTrustRef trust, dispatch_queue_t queue, SecTrustWithErrorCallback result);
static OSStatus replaced_SecTrustEvaluateAsyncWithError(SecTrustRef trust, dispatch_queue_t queue, SecTrustWithErrorCallback result){
    dispatch_async(queue, ^{
        SSKLog(@"Overrided SecTrustEvaluateAsyncWithError!");
        result(
            trust,      // SecTrustRef trust
            1,          // bool result
            NULL        // CFErrorRef error (nullable)
        );  // call the callback with success result
    });
	return 0; // errSecSuccess
}

static OSStatus (*original_SecTrustEvaluateFastAsync)(SecTrustRef trust, dispatch_queue_t queue, SecTrustCallback result);
static OSStatus replaced_SecTrustEvaluateFastAsync(SecTrustRef trust, dispatch_queue_t queue, SecTrustCallback result){
    dispatch_async(queue, ^{
        SSKLog(@"Overrided SecTrustEvaluateFastAsync!");
        result(
            trust,      // SecTrustRef trust
            1           // bool result
        );  // call the callback with success result
    });
	return 0; // errSecSuccess
}

static OSStatus (*original_SecTrustSetPolicies)(SecTrustRef trust, void* policies);
static OSStatus replaced_SecTrustSetPolicies(SecTrustRef trust, void* policies){
    SSKLog(@"Overrided SecTrustEvaluateFastAsync!");
    return 0; // errSecSuccess
}

#pragma mark Manual Pinning ([NSURLSessionDelegate URLSession:didReceiveChallenge:completionHandler:])
// https://developer.apple.com/documentation/foundation/nsurlauthenticationmethodservertrust
// URLSession:didReceiveChallenge:completionHandler: are triggered in CFNetwork from 4 places:
//   -[__NSCFLocalSessionTask _onqueue_didReceiveChallenge:request:withCompletion:] - easy to patch, usually triggers
//   -[__NSCFTCPIOStreamTask _onqueue_sendSessionChallenge:completionHandler:] - easy to patch, hardly triggers
//   -[__NSURLBackgroundSession backgroundTask:didReceiveChallenge:reply:] - hard to patch (have some password auth setup inside), hardly triggers
//   unknown - cannot analysis due to missing xref

void checkChallengeAndOverride(id challenge, void (^completion)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential)) {
	BOOL needOverrideCompletion = NO;

	id protectionSpace = [challenge protectionSpace];
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
static void new__NSCFLocalSessionTask__onqueue_didReceiveChallenge(id self, SEL _cmd, id challenge, id request, void (^completion)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential) ) {
	SSKLog(@"__NSCFLocalSessionTask _onqueue_didReceiveChallenge! protectionSpace: %@", [challenge protectionSpace]);
	checkChallengeAndOverride(challenge, completion);
	// return %orig(challenge, req, completion);
}

static BOOL (*old__NSCFTCPIOStreamTask__onqueue_sendSessionChallenge)(id self, SEL _cmd, id challenge, void (^completion)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential) );
static BOOL new__NSCFTCPIOStreamTask__onqueue_sendSessionChallenge(id self, SEL _cmd, id challenge, void (^completion)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential) ) {
	SSKLog(@"__NSCFTCPIOStreamTask _onqueue_sendSessionChallenge! protectionSpace: %@", [challenge protectionSpace]);
	checkChallengeAndOverride(challenge, completion);
	return YES;
	// return %orig;
}

#pragma mark Dylib Constructor

void hookF(const char *libName, const char *funcName, void *replaceFun, void **origFun) {
    void *libHandle = RTLD_DEFAULT;
    if (libName) {
        libHandle = dlopen(libName, RTLD_NOW);
        if (!libHandle) {
            libHandle = RTLD_DEFAULT;
        }
    }
    void *pFunc = dlsym(libHandle, funcName);
    if (!pFunc) {
        SSKLog(@"Failed to find function %s", funcName);
        return;
    }
#if SUBSTRATE_BUILD
        MSHookFunction(pFunc, replaceFun, origFun);
#else
        if (origFun)
            *origFun = pFunc;
        if (rebind_symbols((struct rebinding[1]){{(char *)funcName, (void *)replaceFun}}, 1) < 0) {
            SSKLog(@"Failed to do fish hook for %s!", funcName);
        }
#endif
}

void hookM(Class _class, SEL _cmd, IMP _new, IMP *_old) {
    if (!_class) {
        return;
    }
#if SUBSTRATE_BUILD
    MSHookMessageEx(_class, _cmd, _new, _old);
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
                return;
            }
        }
        free(_methods);
        _searchedClass = class_getSuperclass(_searchedClass);
    }
#endif
}

__attribute__((constructor)) static void init(int argc, const char **argv)
{
    // Only hook if the preference file says so
    if (shouldHookFromPreference())
    {
        SSKLog(@"Hook enabled.");

        NSProcessInfo *processInfo = [NSProcessInfo processInfo];
        if ([processInfo isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){12, 0, 0}])
        {
            // Support for iOS 12 and 13

            if ([processInfo isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){13, 0, 0}])
            {
                SSKLog(@"iOS 13+ detected");
                // iOS 13 uses SSL_set_custom_verify() which was recently added to BoringSSL
                hookF("/usr/lib/libboringssl.dylib", "SSL_set_custom_verify", (void *) replaced_SSL_set_custom_verify,  (void **) &original_SSL_set_custom_verify);
            }
            else
            {
                SSKLog(@"iOS 12 detected");
                // iOS 12 uses the older SSL_CTX_set_custom_verify()
                hookF("/usr/lib/libboringssl.dylib", "SSL_CTX_set_custom_verify", (void *) replaced_SSL_CTX_set_custom_verify,  (void **) &original_SSL_CTX_set_custom_verify);
            }
            
            // Hook SSL_get_psk_identity() on both iOS 12 and 13
            hookF("/usr/lib/libboringssl.dylib", "SSL_get_psk_identity", (void *) replaced_SSL_get_psk_identity,  (void **) NULL);
        }
		else if ([processInfo isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){11, 0, 0}])
		{
            // Support for iOS 11
            SSKLog(@"iOS 11 detected; hooking nw_tls_create_peer_trust()...");
			hookF("/usr/lib/libnetwork.dylib", "nw_tls_create_peer_trust", (void *) replaced_tls_helper_create_peer_trust,  (void **) &original_tls_helper_create_peer_trust);
		}
        else if ([processInfo isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){10, 0, 0}])
        {
            // Support for iOS 10
            SSKLog(@"iOS 10 detected; hooking tls_helper_create_peer_trust()...");
            hookF(NULL, "tls_helper_create_peer_trust", (void *) replaced_tls_helper_create_peer_trust,  (void **) &original_tls_helper_create_peer_trust);
        }
        else if ([processInfo isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){8, 0, 0}])
        {
            // SecureTransport hooks - works up to iOS 9
            SSKLog(@"iOS 8 or 9 detected; hooking SecureTransport...");
            hookF(NULL, "SSLHandshake",(void *)  replaced_SSLHandshake, (void **) &original_SSLHandshake);
            hookF(NULL, "SSLSetSessionOption",(void *)  replaced_SSLSetSessionOption, (void **) &original_SSLSetSessionOption);
            hookF(NULL, "SSLCreateContext",(void *)  replaced_SSLCreateContext, (void **) &original_SSLCreateContext);
        }

        // CocoaSPDY hooks - https://github.com/twitter/CocoaSPDY
        // TODO: Enable these hooks for the fishhook-based hooking so it works on OS X too
        Class spdyProtocolClass = NSClassFromString(@"SPDYProtocol");
        if (spdyProtocolClass)
        {
            SSKLog(@"CocoaSPDY detected; hooking it...");
            // Disable trust evaluation
            hookM(object_getClass(spdyProtocolClass), NSSelectorFromString(@"setTLSTrustEvaluator:"), (IMP) &newSetTLSTrustEvaluator, (IMP *)&oldSetTLSTrustEvaluator);

            // CocoaSPDY works by getting registered as a NSURLProtocol; block that so the Apps switches back to HTTP as SPDY is tricky to proxy
            Class spdyUrlConnectionProtocolClass = NSClassFromString(@"SPDYURLConnectionProtocol");
            hookM(object_getClass(spdyUrlConnectionProtocolClass), NSSelectorFromString(@"registerOrigin:"), (IMP) &newRegisterOrigin, (IMP *)&oldRegisterOrigin);

            hookM(NSClassFromString(@"NSURLSessionConfiguration"), NSSelectorFromString(@"setprotocolClasses:"), (IMP) &newSetprotocolClasses, (IMP *)&oldSetprotocolClasses);
        }

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

        // hook URLSession:didReceiveChallenge:completionHandler:
        hookM(NSClassFromString(@"__NSCFLocalSessionTask"), NSSelectorFromString(@"_onqueue_didReceiveChallenge:request:withCompletion:"), (IMP) &new__NSCFLocalSessionTask__onqueue_didReceiveChallenge, (IMP *)&old__NSCFLocalSessionTask__onqueue_didReceiveChallenge);
        hookM(NSClassFromString(@"__NSCFTCPIOStreamTask"), NSSelectorFromString(@"_onqueue_sendSessionChallenge:completionHandler:"), (IMP) &new__NSCFTCPIOStreamTask__onqueue_sendSessionChallenge, (IMP *)&old__NSCFTCPIOStreamTask__onqueue_sendSessionChallenge);
    }
    else
    {
        SSKLog(@"Hook disabled.");
    }
}
