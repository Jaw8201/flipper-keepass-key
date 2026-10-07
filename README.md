# KeePass Key for Flipper Zero

A Flipper Zero hardware challenge-response authenticator for KeePassXC.

KeePass Key uses a Flipper Zero as an additional physical factor when unlocking a KeePassXC database. Instead of typing or transmitting a static password, the Flipper responds to a cryptographic challenge using a unique HMAC secret stored on the device.

Use of that secret is protected locally by a private directional-button sequence and explicit physical authorization on the Flipper.

The HMAC secret is never sent to KeePassXC.

> **Status:** Experimental / work in progress.
> This project has successfully completed end-to-end KeePassXC challenge-response testing, but should not yet be relied upon as the sole protection mechanism for an important production database.

## How it works

KeePass Key implements HMAC-SHA1 challenge-response authentication compatible with KeePassXC's hardware challenge-response mechanism.

The current authentication flow is:

1. Unlock KeePass Key on the Flipper using your private directional sequence.
2. Press OK to authorize one USB challenge.
3. The Flipper enters `USB READY`.
4. KeePassXC sends its challenge to the Flipper.
5. The Flipper calculates HMAC-SHA1 using its locally stored 160-bit secret.
6. Only the 20-byte challenge response is returned to KeePassXC.
7. The authorization is immediately consumed.
8. The Flipper relocks.

A second challenge requires the user to authenticate and authorize the device again.

The directional sequence is **not** part of the KeePass cryptographic key. It is a local authorization mechanism controlling access to the HMAC secret.

## Current functionality

### Local authentication

* First-run creation of a private directional sequence
* Configurable sequence length from 8 to 32 directions
* Sequence stored locally rather than compiled into the application
* Concealed sequence entry
* Full-sequence validation
* No indication of which position in an incorrect sequence was wrong
* Explicit OK confirmation before retrying after a failed attempt
* Persistent failed-attempt counter
* Progressive delays following failed attempts
* Delay reapplied after restarting the application
* Manual relocking
* Automatic authorization timeout

### Cryptographic key

* 160-bit HMAC secret
* Generated on the Flipper using `furi_hal_random_fill_buf()`
* Separate from the directional unlock sequence
* Stored in the application's data directory
* HMAC-SHA1 implementation with RFC 2202 self-test
* Key fingerprint for recovery verification
* No HMAC secret embedded in the public source

### Recovery

KeePass Key supports offline backup and restoration of the HMAC secret.

After local authorization, the recovery key can be displayed on the Flipper. The backup is represented as 40 hexadecimal characters corresponding to the 20-byte HMAC secret.

A missing device key can either be:

* generated as a new random key; or
* restored manually from an existing recovery backup.

The restored key can be checked against its short fingerprint.

**The recovery key is equivalent to possession of the authenticator's cryptographic secret. Anyone who obtains it can clone the challenge-response identity of the device. Store it securely and offline.**

### USB challenge-response

The current implementation communicates with the host through the Flipper USB serial interface.

The development protocol accepts:

```text
keepass_challenge <hex challenge>
```

A successful request returns:

```text
OK <40 hexadecimal characters>
```

The response is the 20-byte HMAC-SHA1 result.

The command is rejected unless the user has locally authenticated and explicitly armed USB access.

Only one successful challenge is permitted per authorization.

### KeePassXC integration

A custom KeePassXC driver has been developed and tested alongside this Flipper application.

The driver:

* discovers the Flipper over USB serial
* presents it as a hardware challenge-response device
* uses KeePassXC's hardware-key workflow
* applies KeePassXC-compatible challenge padding
* sends the challenge to KeePass Key
* validates and returns the 20-byte HMAC response
* reports a useful error when the Flipper has not been authorized

End-to-end testing has successfully demonstrated:

```text
KeePassXC
    ↓
password + hardware challenge
    ↓
Flipper Zero / KeePass Key
    ↓
local directional authentication
    ↓
one-use physical authorization
    ↓
HMAC-SHA1 response
    ↓
KeePassXC database unlocked
    ↓
Flipper immediately relocked
```

A locked Flipper correctly refuses the challenge and KeePassXC fails to calculate the database key.

The KeePassXC integration is currently maintained separately from this Flipper application and requires a modified KeePassXC build.

## Security model

KeePass Key separates local authorization from cryptographic authentication.

The system combines:

* **Something you know** — the private directional sequence
* **Something you possess** — the Flipper Zero
* **Explicit physical authorization** — USB challenge-response must be armed on the device
* **A device-specific cryptographic secret** — the 160-bit HMAC key

The directional sequence does not derive, encrypt or replace the HMAC secret.

Possession of the Flipper alone should therefore not normally be sufficient to perform a challenge-response operation through the application interface.

### One-use authorization

Authorization is deliberately short-lived.

After entering the correct directional sequence, the user must explicitly arm USB authentication. A successful host challenge consumes that authorization and immediately returns the application to its locked state.

This prevents an already-authorized device from silently servicing repeated KeePassXC challenges.

### Failed attempts

Incorrect directional sequences trigger progressively longer delays.

The failed-attempt count is persisted so restarting the application does not reset the current protection delay.

Sequence comparison is performed only after the complete sequence has been entered. The interface does not reveal the position of the first incorrect direction.

## Important security limitations

This project should not be considered equivalent to a dedicated hardware security token.

### No secure element

Flipper Zero does not provide the same secret-protection properties as devices specifically designed around secure cryptographic hardware.

The current HMAC key is stored in the application's microSD data storage.

An attacker with sufficient physical access to the device or storage may therefore be able to extract the secret without using the normal KeePass Key interface.

The directional sequence protects **use of the key through the application**; it should not be interpreted as encryption of the HMAC key at rest.

### Recovery key

The recovery key is a complete representation of the HMAC secret.

Anyone possessing it can reproduce the authenticator's cryptographic responses.

Do not:

* commit it to Git
* store it alongside the KeePass database
* send it through chat or email
* include it in screenshots
* use a public or example recovery key for a real database

Keep at least one secure offline backup. Losing both the Flipper's HMAC key and all recovery copies can make a database configured to require that challenge-response key inaccessible.

### Experimental software

This project has not undergone an independent security audit.

Use a disposable KeePassXC database while developing, modifying or testing the project.

Do not migrate an important password database until you understand the recovery process and have independently verified that your recovery backup can reproduce the original authenticator identity.

## First-run setup

On first launch, KeePass Key asks you to create a directional unlock sequence.

The sequence:

* must contain at least 8 directions
* may contain up to 32 directions
* is confirmed before being saved
* is created on the device
* is not contained in this repository

After local authentication, the application can generate a new HMAC key using the Flipper's random-number generator.

Once generated, create and securely record the recovery backup before using the key to protect an important database.

## Recovery procedure

If the HMAC key is missing, KeePass Key presents two choices:

```text
DEVICE KEY SETUP

UP generate new key
DOWN restore backup
BACK to relock
```

Generating a new key creates a new authenticator identity.

It **will not** reproduce the response required by a database configured with an older key.

To recover an existing authenticator, choose restore and enter the complete 40-character hexadecimal recovery key.

After restoration, compare the displayed key fingerprint with the fingerprint recorded when the backup was created.

## Building the Flipper application

### Requirements

Development has primarily been performed with:

* Flipper Zero
* Momentum firmware
* uFBT
* Windows
* microSD card

Install and configure uFBT for the firmware SDK you are targeting.

For the Momentum SDK used during development:

```text
ufbt update --index-url=https://up.momentum-fw.dev/firmware/directory.json
```

From the project directory, build with:

```text
ufbt
```

To build and immediately launch the application on a connected Flipper:

```text
ufbt launch
```

GitHub Actions also performs automated uFBT builds for the repository.

Successful compilation against an SDK does not by itself guarantee that every runtime feature behaves identically across firmware variants. The primary tested development environment is Momentum.

## Installing

Build the application with uFBT and install the resulting `.fap` using your normal Flipper application installation method.

During active development the application can be launched directly with:

```text
ufbt launch
```

Do not copy another user's application data directory as part of installation.

Each installation should create its own:

* directional authorization sequence
* HMAC secret

Only restore an existing HMAC key when intentionally recovering or cloning an authenticator from your own recovery backup.

## KeePassXC setup

The standard KeePassXC build does not currently contain the KeePass Key serial driver used by this project.

A modified KeePassXC build is therefore required.

The tested integration is based on the KeePassXC 2.8.0-beta1 development source and adds a Flipper challenge-response driver alongside the existing hardware-key interfaces.

Once the modified build detects the Flipper, KeePassXC presents it as a hardware challenge-response key.

To add it to a **test database**:

1. Open the database normally.
2. Open **Database Security**.
3. Choose **Add additional protection**.
4. Choose **Add Challenge-Response**.
5. Authenticate on the Flipper using the directional sequence.
6. Press OK on the Flipper to enter `USB READY`.
7. Select the Flipper challenge-response device in KeePassXC.
8. Confirm the database security change.
9. Save the database.

After this change, the database requires the configured credentials **and** the same HMAC challenge-response identity.

Before relying on it, lock the database and perform a complete unlock test.

Then separately test your recovery procedure using a disposable database.

## Protocol behaviour

The serial transport currently uses a simple textual command protocol.

Maximum challenge size is 64 bytes.

KeePassXC challenges shorter than 64 bytes are padded by the host integration to match KeePassXC's hardware challenge-response behaviour.

Possible device responses include:

```text
OK <HMAC-SHA1 response>
ERR authorization_required
ERR key_missing
ERR challenge_length
ERR invalid_hex
```

Temporary challenge and response buffers are cleared where practical after use.

The serial protocol is currently an implementation interface rather than a stable public protocol specification and may change during development.

## Key fingerprint

KeePass Key displays a short identifier derived from the HMAC secret.

The fingerprint is generated from HMAC-SHA1 using a fixed public fingerprint label, with the first four result bytes displayed as eight hexadecimal characters.

For example:

```text
ID: A1B2C3D4
```

This is an identifier, **not a secret** and not a substitute for the recovery key.

Its purpose is to help confirm that a restored key matches the expected authenticator.

## Repository safety

This repository is designed so that cloning it does not clone somebody else's credentials.

The source should never contain:

* a personal directional sequence
* an HMAC secret
* a recovery key
* a KeePass database password
* a KeePass key file
* production database material

The directional sequence is created during first-run configuration.

The HMAC secret is generated locally on the Flipper or manually restored from the owner's recovery backup.

Generated build output and local editor files are excluded from version control.

## Development status

### Working

* First-run directional sequence creation
* Persistent sequence configuration
* Concealed full-sequence authentication
* Persistent progressive failed-attempt delays
* HMAC-SHA1 implementation
* RFC 2202 HMAC self-test
* Hardware-random HMAC key generation
* Persistent HMAC key storage
* Key fingerprint
* Recovery-key display
* Manual recovery-key restoration
* Recovery verification
* USB serial challenge-response
* One-use USB authorization
* Immediate relocking after successful response
* KeePassXC device discovery
* KeePassXC HMAC challenge-response
* Real database re-keying with password + Flipper
* Real database unlock with password + Flipper
* Correct rejection when the Flipper is not authorized

### Still to improve

* Harden device discovery so generic STM32 serial devices cannot be mistaken for KeePass Key
* Define a non-consuming device/protocol identification mechanism
* Improve stable device identity across systems and USB ports
* Harden host-side response parsing
* Improve KeePassXC integration packaging and deployment
* Automate Qt SerialPort runtime deployment for Windows builds
* Add automated integration tests
* Review device-ID collision handling
* Review and document cross-platform behaviour
* Final UI polish
* Independent security review

## Tested milestone

The tag:

```text
flipper-cr-working-v1
```

marks the Flipper firmware used for the first successful end-to-end KeePassXC challenge-response tests.

The matching KeePassXC integration was also preserved at its corresponding known-good development state.

## Project scope

KeePass Key is an experimental authenticator project.

It is **not**:

* a KeePass database stored on the Flipper
* a BadUSB password typer
* a replacement for the KeePass master password
* a YubiKey emulator claiming equivalent hardware security
* a secure-element implementation

Its purpose is to explore using Flipper Zero as a locally authorized HMAC challenge-response factor for KeePassXC.

## License

MIT License.

See `LICENSE` for details.
