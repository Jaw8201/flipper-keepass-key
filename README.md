# KeePass Key for Flipper Zero

A Flipper Zero hardware authentication project for KeePassXC.

The goal of KeePass Key is to use a Flipper Zero as an additional physical authentication factor when unlocking a KeePassXC database.

Rather than simply typing a static password or key through BadUSB, the finished system is intended to use cryptographic challenge-response authentication. The cryptographic secret remains on the Flipper and is only used after local authorization on the device.

## Project goals

The intended authentication flow is:

1. KeePassXC requests authentication.
2. The Flipper Zero receives a cryptographic challenge.
3. The user unlocks the Flipper authenticator using a private directional-button sequence.
4. The Flipper requires physical confirmation.
5. The Flipper computes the challenge response using a locally stored cryptographic secret.
6. Only the response is returned to the computer.
7. Authorization is immediately revoked after use.

The cryptographic secret should never be transmitted to the host computer.

## Current functionality

The Flipper application currently provides:

* Directional-button authentication
* Concealed sequence entry
* Full-sequence validation
* No indication of which sequence position was incorrect
* Progressive delays following failed attempts
* Explicit OK confirmation before retrying a failed sequence
* Temporary authorized state
* Automatic authorization timeout
* Manual relocking

## Planned functionality

Development is intended to add:

* Persistent failed-attempt protection
* Cryptographic key generation and provisioning
* Protected key storage
* HMAC challenge-response
* USB communication with the host
* KeePassXC integration
* Single-use authorization
* Physical confirmation before each authentication request
* Recovery and backup procedures

## Security model

The directional sequence is **not** the cryptographic key protecting the KeePass database.

It acts as local authorization allowing the Flipper to use a separate cryptographic secret.

The intended design therefore combines:

* Something the user knows — the directional sequence
* Something the user possesses — the Flipper Zero
* Explicit physical authorization — confirmation on the device
* A cryptographic secret retained by the authenticator

The project is designed so that possession of the Flipper alone should not be sufficient to authorize a KeePass unlock.

## Development environment

Currently developed and tested with:

* Flipper Zero
* Momentum Firmware
* uFBT
* Windows
* KeePassXC

## Development status

**Experimental / work in progress.**

This project is currently under active development and should not yet be relied upon as the sole protection mechanism for a production KeePass database.

Development and testing should be performed using a disposable test database until the complete authentication and recovery process has been implemented and verified.

## Security warning

Do not commit personal authentication sequences, cryptographic secrets, KeePass passwords, key files, or other sensitive credentials to a repository.

Before publishing or distributing this project, replace any embedded personal authentication sequence with a safe example or configuration mechanism.

## License

MIT License.
