# SSL Kill Switch 3

Next Generation of iOS Tweak SSLKillSwitch (https://github.com/nabla-c0d3/ssl-kill-switch2) with much more functionality!

## What's New?

- [FIXED] Fishhook Support (iOS 15+, ARM64e), so that you can hook in non-jailbreak era

- [ADDED] Hooks SecIsInternalRelease, so AppleServerAuthenticationNoPinning can be set
- [ADDED] Hooks to Disable Security SecTrustEvaluate series function
- [ADDED] Hooks to Disable [NSURLSessionDelegate URLSession:didReceiveChallenge:completionHandler:]

## Usage

1. Grab a build from https://github.com/NyaMisty/ssl-kill-switch3/releases, or build it yourself
    - Note: nightly build also available in GitHub CI
2. (If Jailbroken) Simply install the deb into system using `dpkg -i`, and check Settings after respring
3. (If Not Jailbroken) Use Signing tools like *Sideloadly* or *ESign* to inject the **dylib** into IPA and install it

## Building

Note: **Theos** Needed!

- Substrate Version (jailbreak version):
    ```
    make package
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
