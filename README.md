# KeePass Key for Flipper Zero

A Flipper Zero hardware authentication project for KeePassXC.

KeePass Key uses a Flipper Zero as an additional physical authentication factor when unlocking a KeePassXC database.

Rather than transmitting a static password or key through BadUSB, KeePass Key uses cryptographic challenge-response authentication. The cryptographic secret remains on the Flipper and is only used after local authorization on the device.

## Authentication flow

The current authentication flow is:

1. KeePassXC discovers the KeePass Key device over USB.
2. KeePassXC verifies that the device is running the KeePass Key application.
3. The user unlocks the Flipper authenticator using a private directional-button sequence.
4. The user explicitly confirms authorization on the Flipper.
5. KeePassXC sends a cryptographic challenge to the Flipper.
6. The Flipper computes the HMAC response using its locally stored cryptographic secret.
7. Only the challenge response is returned to KeePassXC.
8. The authorization is consumed after the challenge and the Flipper returns to its locked state.

The cryptographic secret is never transmitted to the host computer.

## Current functionality

### Local authentication

The Flipper application currently provides:

* Directional-button authentication
* Configurable sequence length
* Concealed sequence entry
* Full-sequence validation
* No indication of which sequence position was incorrect
* Progressive delays following failed attempts
* Explicit OK confirmation before retrying a failed sequence
* Temporary authorized state
* Automatic authorization timeout
* Manual relocking

### Cryptographic authentication

The application currently provides:

* Cryptographically generated HMAC key
* Local key provisioning
* Protected credential storage on the Flipper
* HMAC-SHA1 challenge-response
* Fixed-length challenge handling compatible with the KeePassXC integration
* Key fingerprint for identification and recovery verification
* HMAC key backup and recovery
* Provisioned-key verification
* Single-use challenge authorization
* Automatic return to the locked state after a successful challenge

The directional authentication sequence is separate from the cryptographic key.

### USB communication

KeePass Key communicates with KeePassXC through the Flipper's USB serial interface.

The application exposes two host commands:

* `keepass_info` — identifies the application and protocol without consuming authorization
* `keepass_challenge` — performs the authenticated challenge-response operation

`keepass_info` returns the KeePass Key protocol version and a non-secret key fingerprint.

The discovery process deliberately does **not** perform a cryptographic challenge. This is important because authorization is single-use.

### KeePassXC integration

The project includes a KeePassXC integration which:

* Detects the Flipper over USB
* Uses the Flipper's USB VID/PID only as an initial candidate filter
* Verifies the running KeePass Key application using `keepass_info`
* Supports stable device identification
* Sends KeePassXC challenge data to the Flipper
* Validates the returned 20-byte HMAC response
* Rejects malformed or non-hexadecimal responses
* Handles authorization, key and challenge errors
* Supports the existing KeePassXC hardware-key selection mechanism

An unrelated USB serial device with the same generic STM32 USB identifiers should therefore not be accepted as a KeePass Key device unless it responds correctly to the KeePass Key protocol.

## Security model

The directional sequence is **not** the cryptographic key protecting the KeePass database.

It acts as local authorization allowing the Flipper to use a separate cryptographic secret.

The system therefore combines:

* **Something the user knows** — the directional sequence
* **Something the user possesses** — the Flipper Zero
* **Explicit physical authorization** — confirmation on the device
* **A cryptographic secret** — retained by the authenticator

The project is designed so that possession of the Flipper alone should not be sufficient to authorize a KeePass unlock.

The cryptographic secret is not sent to the host computer.

Authorization is intentionally temporary and is consumed by the challenge-response operation.

## Key management

The Flipper generates its own HMAC credential rather than receiving the secret from KeePassXC.

The application provides:

* HMAC key generation
* Persistent local storage
* Key fingerprint display
* Backup and recovery
* Verification of a recovered key

The fingerprint is an identifier for verifying that the expected cryptographic key is present. It is not the cryptographic key itself.

Authentication sequences, HMAC keys and recovery material must never be committed to the source repository.

## Device discovery

KeePassXC does not rely solely on the Flipper's USB VID/PID to identify the authenticator.

Discovery works in two stages:

1. Identify candidate USB serial devices using the expected VID/PID.
2. Send the non-consuming `keepass_info` command and require the expected KeePass Key protocol response.

This means the KeePass Key application must actually be running for the device to be presented as an available KeePassXC hardware key.

Discovery does not require the user to unlock the Flipper and does not consume a one-use authorization.

## Development environment

Currently developed and tested with:

* Flipper Zero
* Momentum Firmware
* uFBT
* Windows
* KeePassXC
* Qt 6 SerialPort

## Development status

**Experimental / work in progress.**

The complete basic challenge-response authentication flow is now working end-to-end between the Flipper application and a modified KeePassXC build.

The following have been tested:

* Flipper local authentication
* HMAC key provisioning
* USB challenge-response
* Single-use authorization
* Automatic relocking
* KeePassXC device discovery
* Non-consuming device identification
* KeePassXC challenge-response
* Successful KeePass database unlocking
* Rejection of an inactive KeePass Key application during discovery
* HMAC response format validation

The project should nevertheless **not yet be relied upon as the sole protection mechanism for a production KeePass database**.

Development and further testing should be performed using a disposable test database until the complete authentication, recovery and deployment process has been thoroughly reviewed.

## Security warning

Do not commit:

* Personal authentication sequences
* HMAC cryptographic secrets
* KeePass passwords
* KeePass key files
* Recovery secrets
* Other sensitive credentials

The repository should contain only example or generated development configuration.

The directional authentication sequence should not be embedded as a personal secret in a publicly distributed build.

## Repository hygiene

Generated build output and editor-specific files are excluded from the repository.

The repository should contain source code and project configuration rather than locally generated binaries or development environment files.

## License

MIT License.