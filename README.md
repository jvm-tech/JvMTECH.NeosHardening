# JvMTECH.NeosHardening Package for Neos CMS #
[![Latest Stable Version](https://poser.pugx.org/jvmtech/neos-hardening/v/stable)](https://packagist.org/packages/jvmtech/neos-hardening)
[![License](https://poser.pugx.org/jvmtech/neos-hardening/license)](https://packagist.org/packages/jvmtech/neos-hardening)

Harden request headers, login interface and passwords to increase backend security. 

## Installation
```
composer require jvmtech/neos-hardening
```

## Active by default

- Remove Neos version info from request headers *
- Set min password strength requirements

## Optional features

- Change the default login url "/neos" to something like "/neos-random-suffix" *:
  ```
  JvMTECH:
    NeosHardening:
      loginUri: 'neos-random-suffix'
  ```
- Replace the dynamic login url check with a custom RegEx (not needed if you just replace `loginUri`):
  ```
  JvMTECH:
    NeosHardening:
      loginUriRegex: '/^(neos)?($|\/)/'
  ```
- Limit login interface access to specified ip addresses:
  ```
  JvMTECH:
    NeosHardening:
    allowedIPs:
      IPv4:
        - '172.20.30.40'
        - '172.20.0.0/24'
      IPv6:
        - '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
  ```
- Define password strength requirements, defaults:
  ```
  JvMTECH:
    NeosHardening:
      checkPasswordStrengthOnAddUser: true
      checkPasswordStrengthOnSetUserPassword: true
      passwordRequirements:
        minLength: 8
        upperAndLowerCase: true
        numbers: true
        specialChars: false
        maxConsecutiveLetters: 0 # disabled
        maxConsecutiveNumbers: 0 # disabled
  ```
- An example for secure passwords (should be your standard because you use a password manager, right? 😉):
  ```
  JvMTECH:
    NeosHardening:
      passwordRequirements:
        minLength: 16
        upperAndLowerCase: true
        numbers: true
        specialChars: true
        maxConsecutiveLetters: 3
        maxConsecutiveNumbers: 3

  # "djxAHQC0bzc_tjd9nmg" would fail
  # "djx@HQC0bzc_tjd9nmg" would work
  ```
- Disable user on too many failed login attempts:
  ```
  JvMTECH:
    NeosHardening:
      checkFailedLogins: true
      blockAfterFailedLogins: 5
  ```
- Prevent reuse of old passwords:
  ```
  JvMTECH:
    NeosHardening:
      checkPasswordHistory: true
      passwordHistoryLength: 10
  ```
- - Force password reset on new account creation or admin update:
  ```
  JvMTECH:
    NeosHardening:
      forcePasswordResetAfterUpdate: true
  ```

## *) Why hiding stuff?

Hiding the Neos version in the request headers and moving the login to an new url is nothing else than "[security by obsurity](https://en.wikipedia.org/wiki/Security_through_obscurity)".

Yes. But it's another layer to make it a little bit harder to get into your system. Therefore, it's a low-hanging fruit we should take.

---

by [jvmtech.ch](https://jvmtech.ch)
