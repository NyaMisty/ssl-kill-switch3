# SSL Kill Switch 3

Next Generation of iOS Tweak SSLKillSwitch (https://github.com/nabla-c0d3/ssl-kill-switch2) with much more functionality!

## What's New?

- [FIXED] Fishhook Support (iOS 15+, ARM64/ARM64e), so that you can hook in non-jailbreak era
- [FIXED] Rootless Support (iOS 15+, ARM64/ARM64e), happy rootless :)

- [ADDED] Hooks SecIsInternalRelease, so AppleServerAuthenticationNoPinning can be set
    - see https://vtky.github.io/2021/01/05/apple-globalpreferences for more
- [ADDED] Hooks to Disable Security SecTrustEvaluate series function
- [ADDED] Hooks to Disable [NSURLSessionDelegate URLSession:didReceiveChallenge:completionHandler:]
- [ADDED] Various bypass technique from [sensepost/objection](https://github.com/sensepost/objection)
    - AFNetworking, TrustKit, Cordova SSLCertificateChecker-PhoneGap-Plugin

## Usage

1. Grab a build from https://github.com/NyaMisty/ssl-kill-switch3/releases, or build it yourself
    - Note: nightly build also available in GitHub CI
2. (For New Rootless Jailbreak, like Dopamine) Download `+rootless` deb, and open it in Sileo (or install the deb using `dpkg -i`), then check Settings after respring
2. (For Old Rootful Jailbreak, like checkra1n) Download `+rootful` deb, and open it in Sileo (or install the deb using `dpkg -i`), then check Settings after respring
3. (If Not Jailbroken) Use Signing tools like *Sideloadly* or *ESign* to inject the **dylib** into IPA and install it

## Building

Note: **Theos** Needed! **MacOS** is also needed if you are building for rootless

- Substrate Version (jailbreak version):
    - Rootful:
        ```
        make package
        ls packages
        ```
    - Rootless:
        ```
        make package ROOTLESS=1
        ls packages
        ```
- Fishhook Version (non-jailbreak version)
    - Debug Version:
        ```
        make FISHHOOK=1
        ls .theos/obj/debug/SSLKillSwitch2.dylib
        ```
    - Release Version:
        ```
        make FISHHOOK=1 FINALPACKAGE=1
        ls .theos/obj/SSLKillSwitch2.dylib
        ```
