# KeePass Key for Flipper Zero

### A hardware-based cryptographic authenticator for KeePassXC

KeePass Key transforms a Flipper Zero into a physical authentication device for KeePassXC, combining cryptographic challenge-response authentication with local access control, brute-force protection, single-use authorisation and automatic relocking.

Unlike conventional Flipper Zero password applications that use BadUSB to type stored credentials, KeePass Key never transmits its cryptographic secret during normal authentication. Instead, it calculates a response to a challenge supplied by KeePassXC.

Before the Flipper can perform this operation, it must be unlocked using a private directional-button sequence and explicitly authorised.

The project demonstrates how embedded cryptography, USB communication, authentication state machines and desktop application integration can be combined to create a functional hardware authentication system.

**Status:** Working experimental prototype. The complete authentication process has been tested successfully with a modified KeePassXC build.

> **Security notice:** KeePass Key is an experimental project and has not undergone an independent security audit. The Flipper Zero does not provide hardware-backed secure key storage equivalent to a dedicated security token.

---

## TL;DR — Technical Overview

**KeePass Key is an experimental hardware challenge-response authenticator that integrates the Flipper Zero with KeePassXC through a custom USB serial protocol and modified KeePassXC hardware-key interface.**

The system implements **HMAC-SHA1 challenge-response authentication using a device-generated 160-bit cryptographic secret**, combined with a local authentication state machine that controls when cryptographic operations are permitted.

Rather than transmitting static credentials or emulating keyboard input, KeePass Key receives a challenge derived from KeePassXC's database-unlocking process, computes a 20-byte HMAC response and returns only the result. The underlying secret is never transmitted during normal authentication.

### Security architecture

- **Cryptographic authentication:** HMAC-SHA1 implementation verified against RFC 2202 test vectors, with 160-bit keys generated using the Flipper's hardware RNG.
- **Local access control:** Configurable 8–32 input directional authentication sequence, concealed input, full-sequence validation and persistent progressive brute-force delays.
- **Finite-state authorisation:** Explicit separation of locked, authenticated and armed states, with a 30-second authorisation window and single-use challenge execution.
- **USB protocol:** Custom serial command interface supporting non-consuming device identification, validated hexadecimal challenges, structured error responses and automatic relocking.
- **KeePassXC integration:** Custom Qt 6 SerialPort driver implementing two-stage USB discovery, protocol-version verification, stable device identification and strict HMAC response validation.
- **Credential management:** On-device key generation, persistent credential storage, authorised backup, hexadecimal recovery and HMAC-derived key fingerprint verification.
- **Memory hygiene:** Clearing of sensitive temporary buffers following relevant cryptographic and credential-management operations.

### Authentication sequence

```text
KeePassXC                         Flipper Zero
    |                                  |
    |-------- keepass_info ----------->|
    |<--- Protocol + fingerprint ------|
    |                                  |
    |                          Directional sequence
    |                          validated locally
    |                                  |
    |                          Explicit OK confirmation
    |                          arms one operation
    |                                  |
    |---- keepass_challenge(hex) ----->|
    |                                  |
    |                          Validate challenge
    |                          Verify authorisation
    |                          HMAC-SHA1(key, challenge)
    |                                  |
    |<------- 20-byte HMAC ------------|
    |                                  |
    |                          Consume authorisation
    |                          Clear authorised state
    |                          Return to LOCKED
    |                                  |
    v                                  v
Database unlocking               Await next sequence
```

The Flipper application is distributed as a standalone `.fap`, compiled using uFBT against the Momentum Firmware SDK. Desktop integration is implemented through modifications to KeePassXC's existing hardware challenge-response infrastructure.

**Security boundary:** The HMAC credential is stored on removable microSD storage, not within a secure element. Local authentication and retry restrictions are software-enforced and do not protect against unrestricted physical extraction or modification of the stored credential.

**Development status:** Functional end-to-end prototype. USB discovery, local authentication, HMAC calculation, single-use authorisation, automatic relocking and KeePassXC database unlocking have been demonstrated. Further recovery-path hardening, security review and compatibility testing remain outstanding.

---

## Table of Contents

1. [How KeePass Key Works](#1-how-keepass-key-works)
2. [Understanding Challenge-Response Authentication](#2-understanding-challenge-response-authentication)
3. [The Complete Authentication Process](#3-the-complete-authentication-process)
4. [Directional Authentication](#4-directional-authentication)
5. [Cryptographic Key Generation](#5-cryptographic-key-generation)
6. [Credential Storage](#6-credential-storage)
7. [Single-Use Authorisation](#7-single-use-authorisation)
8. [USB Communication Protocol](#8-usb-communication-protocol)
9. [KeePassXC Integration](#9-keepassxc-integration)
10. [Credential Backup and Recovery](#10-credential-backup-and-recovery)
11. [Key Fingerprints](#11-key-fingerprints)
12. [Building the Flipper Application](#12-building-the-flipper-application)
13. [Momentum Firmware Integration](#13-momentum-firmware-integration)
14. [Initial Setup](#14-initial-setup)
15. [Authenticating with KeePassXC](#15-authenticating-with-keepassxc)
16. [Security Architecture](#16-security-architecture)
17. [Threat Model and Limitations](#17-threat-model-and-limitations)
18. [Testing and Verification](#18-testing-and-verification)
19. [Development Status](#19-development-status)
20. [Technical Significance](#20-technical-significance)
21. [License](#license)

---

## 1. How KeePass Key Works

KeePassXC supports challenge-response authentication as an additional component of its database-unlocking process.

KeePass Key implements this functionality using a Flipper Zero connected through USB.

The authentication system combines four distinct elements:

- **Physical possession:** The Flipper Zero must be connected to the computer.
- **Local authentication:** A private directional-button sequence must be entered.
- **Explicit authorisation:** A separate confirmation permits one cryptographic operation.
- **Cryptographic authentication:** The Flipper calculates an HMAC-SHA1 response using a locally stored secret.

These elements work together to prevent the application from automatically responding to authentication requests simply because the device is connected.

### Why not use BadUSB?

Many password-related Flipper applications emulate a keyboard and type a stored password.

KeePass Key uses a fundamentally different approach.

| Feature | BadUSB password entry | KeePass Key |
|---|---|---|
| Authentication method | Keyboard emulation | Cryptographic challenge-response |
| Static password transmitted | Yes | No |
| Secret remains on device during authentication | No | Yes |
| Challenge-dependent response | No | Yes |
| Local authentication | Implementation-dependent | Required |
| Explicit physical confirmation | Implementation-dependent | Required |
| Single-use authorisation | Implementation-dependent | Yes |
| Automatic relocking | Implementation-dependent | Yes |
| KeePassXC hardware-key integration | No | Yes |
| Credential backup and recovery | Implementation-dependent | Yes |

The fundamental difference is that KeePassXC receives the result of a cryptographic calculation rather than the secret used to produce it.

[↑ Back to top](#keepass-key-for-flipper-zero)

---

## 2. Understanding Challenge-Response Authentication

Challenge-response authentication allows a device to demonstrate possession of a cryptographic secret without transmitting that secret.

KeePass Key uses **HMAC-SHA1**, a keyed message authentication algorithm.

HMAC stands for *Hash-based Message Authentication Code*.

The calculation can be represented as:

```text
Response = HMAC-SHA1(SecretKey, Challenge)
```

Three components are involved:

1. **Secret key:** A randomly generated 160-bit credential stored on the Flipper.
2. **Challenge:** Data supplied by KeePassXC during database unlocking.
3. **Response:** A 20-byte HMAC value calculated from the secret and challenge.

### Example

KeePassXC sends a challenge:

```text
Challenge:
A1B2C3D4E5F6...
```

The Flipper performs:

```text
HMAC-SHA1(
    SecretKey,
    Challenge
)
```

The resulting response is returned as 40 hexadecimal characters:

```text
OK <40 hexadecimal characters>
```

KeePassXC incorporates the response into its database-unlocking process.

The actual integration uses KeePassXC's challenge data and the padding required by its hardware challenge-response mechanism.

### Why this is more secure than transmitting a password

The cryptographic secret is not included in the response.

An observer who captures a challenge and its corresponding response cannot directly recover the HMAC key from those values.

A response calculated for one challenge will not generally be valid for another.

Consequently, the authentication system does not depend on repeatedly transmitting a reusable password.

### Why HMAC-SHA1?

HMAC-SHA1 produces a 160-bit authentication response and is compatible with the challenge-response mechanism used by KeePassXC's existing hardware-key infrastructure.

Although SHA-1 is no longer recommended for collision-resistant digital signatures, HMAC-SHA1 has different security properties because it incorporates a secret key.

The project includes a known-answer test based on **RFC 2202** to verify the HMAC implementation.

[↑ Back to top](#keepass-key-for-flipper-zero)

---

## 3. The Complete Authentication Process

KeePass Key uses a controlled, multi-stage authentication process.

### Stage 1 — USB device discovery

KeePassXC searches for compatible USB serial devices.

The expected USB vendor and product identifiers are used to identify potential Flipper devices.

However, these identifiers alone are not sufficient.

KeePassXC sends:

```text
keepass_info
```

The application responds with its protocol identifier, version and key fingerprint:

```text
OK KEEPASS_KEY 1 28E46ED3
```

This establishes that the connected device is responding to the KeePass Key application protocol.

Discovery does not require local authentication and does not consume an authorisation.

### Stage 2 — Local authentication

The Flipper displays its locked interface.

Authentication requires a private sequence using the directional buttons:

```text
UP
DOWN
LEFT
RIGHT
```

The sequence is created during initial setup.

Supported lengths range from **8 to 32 directional inputs**.

The sequence is stored locally rather than embedded in the application source code.

The actual directions are concealed during entry.

### Stage 3 — Sequence validation

The application validates the completed sequence.

Incorrect attempts produce a generic error without revealing which position was wrong.

Repeated failures trigger progressively longer delays.

The failure counter is stored persistently so that restarting the application does not automatically reset the attempt history.

### Stage 4 — Temporary authorisation

After successful sequence validation, the Flipper enters an authorised state.

This state has a maximum duration of **30 seconds**.

The device is not yet permitted to process a cryptographic challenge.

### Stage 5 — Explicit confirmation

Pressing OK arms the authenticator for one challenge-response operation.

This separates local authentication from permission to use the cryptographic key.

The confirmation does not extend the original authorisation deadline.

### Stage 6 — Challenge reception

KeePassXC sends a challenge through USB:

```text
keepass_challenge <hexadecimal_challenge>
```

The Flipper checks that:

- The challenge is present.
- The hexadecimal input is valid.
- The challenge length is supported.
- A cryptographic key is provisioned.
- The device is explicitly authorised.

Invalid requests are rejected.

### Stage 7 — Cryptographic response

The Flipper calculates:

```text
HMAC-SHA1(SecretKey, Challenge)
```

The resulting 20-byte response is returned to KeePassXC.

The secret key remains on the Flipper.

### Stage 8 — Automatic relocking

After a successful challenge-response operation, the application immediately:

1. Consumes the authorisation.
2. Clears the authorised state.
3. Returns to the locked interface.

Another cryptographic operation requires the authentication sequence and confirmation to be completed again.

[↑ Back to top](#keepass-key-for-flipper-zero)

---

## 4. Directional Authentication

KeePass Key implements its own local authentication system using the Flipper's directional controls.

The authentication sequence is independent of the cryptographic secret.

It acts as permission to use the stored HMAC credential rather than forming part of that credential.

### Configurable sequence length

Sequences can contain between 8 and 32 inputs.

Each position has four possible directions.

The theoretical number of combinations is:

```text
4^N
```

Where `N` represents the sequence length.

| Sequence length | Possible combinations |
|---|---:|
| 8 | 65,536 |
| 12 | 16,777,216 |
| 16 | 4,294,967,296 |
| 20 | 1,099,511,627,776 |
| 24 | 281,474,976,710,656 |
| 32 | 18,446,744,073,709,551,616 |

These values assume independently and uniformly selected directions.

Predictable patterns and repeated sequences can substantially reduce practical security.

### Concealed input

The application does not reveal the actual directions being entered.

This reduces casual observation of the authentication sequence.

### Full-sequence validation

The complete sequence is evaluated without revealing whether individual positions were correct.

An incorrect attempt displays:

```text
Incorrect

Press OK to retry
```

This avoids providing position-by-position feedback that could simplify guessing.

### Progressive brute-force protection

Repeated incorrect attempts trigger increasing delays.

| Failed attempts | Delay |
|---|---:|
| 1–3 | 1 second |
| 4 | 5 seconds |
| 5 | 15 seconds |
| 6 | 60 seconds |
| 7 onwards | 5 minutes |

The failure counter is persisted in application storage.

Restarting the application does not simply reset the recorded failure count.

These restrictions are enforced by software and are not equivalent to hardware-enforced retry limits provided by a secure element.

[↑ Back to top](#keepass-key-for-flipper-zero)

---

## 5. Cryptographic Key Generation

KeePass Key generates its authentication credential directly on the Flipper Zero.

The application uses the device's hardware random-number-generation interface:

```c
furi_hal_random_fill_buf()
```

This produces a randomly generated **20-byte (160-bit) HMAC key**.

The key is generated independently for each installation.

It is not derived from the directional authentication sequence.

### Why generate the key on-device?

Local generation avoids transmitting the credential from a computer during initial provisioning.

It also allows separate devices to generate independent cryptographic credentials.

The key is not displayed during normal provisioning.

Sensitive temporary buffers are cleared after relevant operations.

### Cryptographic verification

The HMAC-SHA1 implementation includes a self-test based on RFC 2202.

The test compares a calculated HMAC against a known expected result.

This helps identify implementation errors in the cryptographic calculation.

A successful known-answer test does not, by itself, establish that the entire implementation is free from vulnerabilities.

[↑ Back to top](#keepass-key-for-flipper-zero)

---

## 6. Credential Storage

The HMAC credential is stored persistently in the application's dedicated microSD directory.

```text
/ext/apps_data/keepass_key/
```

The credential file is:

```text
hmac_key.bin
```

The application uses this credential when processing authorised challenges.

The key is not transmitted through the normal USB authentication protocol.

### Physical security limitations

The Flipper Zero does not contain a dedicated secure element for protecting the HMAC credential.

The secret is stored on removable media.

An attacker with unrestricted access to the microSD card may be able to extract the credential directly.

The directional sequence restricts access through the application interface, but it does not encrypt the underlying credential file.

KeePass Key therefore provides software-controlled access to a cryptographic credential rather than hardware-enforced, non-exportable key storage.

This distinction is important when comparing the project with dedicated security tokens.

[↑ Back to top](#keepass-key-for-flipper-zero)

---

## 7. Single-Use Authorisation

One of KeePass Key's central security mechanisms is its single-use authorisation model.

Successful local authentication does not create an indefinitely available cryptographic service.

Instead, the application maintains separate authentication states.

```text
LOCKED
   |
   | Correct directional sequence
   v
AUTHORISED
   |
   | Explicit OK confirmation
   v
ARMED
   |
   | Valid cryptographic challenge
   v
HMAC RESPONSE
   |
   | Authorisation consumed
   v
LOCKED
```

The authorised state expires after 30 seconds.

Pressing OK arms one response without extending that deadline.

After a successful challenge, the application returns to the locked state.

Pressing BACK can also cancel authorisation and relock the device.

### Why separate authentication and authorisation?

A connected computer should not automatically gain access to the cryptographic function simply because the directional sequence has been entered.

Requiring a separate confirmation introduces an additional deliberate action before the secret can be used.

Single-use authorisation also limits the number of cryptographic operations available during one successful authentication.

This reduces the opportunity for repeated requests from a connected host.

It does not, however, prevent a compromised host from attempting to use the single authorised operation.

[↑ Back to top](#keepass-key-for-flipper-zero)

---

## 8. USB Communication Protocol

KeePass Key communicates through the Flipper Zero's USB serial interface.

The protocol provides two primary commands.

### Device identification

```text
keepass_info
```

Example response:

```text
OK KEEPASS_KEY 1 28E46ED3
```

The response contains:

- Application identifier
- Protocol version
- Non-secret key fingerprint

If no credential has been provisioned:

```text
OK KEEPASS_KEY 1 UNPROVISIONED
```

This command does not require local authorisation.

It also does not consume an armed challenge-response operation.

### Cryptographic challenge

```text
keepass_challenge <hexadecimal_challenge>
```

A successful request returns:

```text
OK <40 hexadecimal characters>
```

The application validates the request before calculating the HMAC.

Supported error responses include:

```text
ERR key_missing
ERR challenge_length
ERR invalid_hex
ERR authorization_required
```

The protocol rejects malformed or unauthorised requests.

After a successful response, the device immediately relocks.

### Input validation

The challenge parser checks hexadecimal formatting and length.

The current protocol supports non-empty challenges up to 64 bytes.

The response is a fixed-length, 20-byte HMAC-SHA1 value encoded as 40 hexadecimal characters.

These checks prevent malformed inputs from being silently accepted as valid authentication requests.

[↑ Back to top](#keepass-key-for-flipper-zero)

---

## 9. KeePassXC Integration

KeePass Key includes a custom KeePassXC integration implemented using Qt 6 SerialPort.

The integration connects to KeePassXC's existing hardware challenge-response infrastructure.

### Two-stage device discovery

The discovery mechanism deliberately avoids relying exclusively on USB vendor and product identifiers.

**Stage 1: USB filtering**

KeePassXC identifies candidate devices using the expected USB identifiers.

**Stage 2: Protocol verification**

Each candidate receives:

```text
keepass_info
```

The integration requires a correctly formatted KeePass Key protocol response.

This reduces accidental identification of unrelated USB serial devices.

The identification response is not cryptographically authenticated and can theoretically be imitated by another device implementing the protocol.

### Stable device identification

The integration derives a stable numerical identifier from USB device information.

This allows the authenticator to appear within KeePassXC's hardware-key selection interface.

### Response validation

KeePassXC checks the returned challenge-response data.

The response must contain:

- The expected success prefix.
- Exactly 40 hexadecimal characters.
- A correctly formatted 20-byte HMAC value.

Malformed responses are rejected.

### Database unlocking

When a database is configured to require the Flipper authenticator, KeePassXC sends its challenge to the device.

The Flipper calculates the HMAC response.

KeePassXC incorporates that response into its normal database-unlocking process.

The Flipper does not receive the database password or database contents.

**The integration requires a modified KeePassXC build. Standard KeePassXC installations do not currently include this custom Flipper interface.**

[↑ Back to top](#keepass-key-for-flipper-zero)

---

## 10. Credential Backup and Recovery

Cryptographic challenge-response authentication depends on retaining access to the correct secret.

If the original HMAC credential is lost, a replacement device generating a different key will not reproduce the same responses.

KeePass Key therefore includes a credential backup and recovery mechanism.

### Recovery code

The 160-bit HMAC key can be represented as 40 hexadecimal characters.

The application provides an authorised recovery interface for displaying this value.

Access to the backup display requires deliberate local confirmation.

The recovery display has a five-minute timeout.

### Restoring a credential

The application supports manually entering an existing recovery code.

The hexadecimal input interface allows the original credential to be reconstructed.

After restoration, the application can calculate the same HMAC responses as the original installation.

This allows recovery after:

- Replacing a microSD card.
- Reinstalling firmware.
- Reinstalling the application.
- Replacing a damaged Flipper.
- Restoring a previous authentication configuration.

### Recovery security

The recovery code is the actual cryptographic credential represented in hexadecimal.

Anyone possessing it may be able to reproduce the authenticator's responses.

Recovery material therefore requires the same protection as the original secret.

The recovery and credential-replacement paths remain areas for additional security hardening.

[↑ Back to top](#keepass-key-for-flipper-zero)

---

## 11. Key Fingerprints

KeePass Key generates a short fingerprint to identify the provisioned HMAC credential.

The fingerprint is calculated using a dedicated identification message:

```text
KeePass Key fingerprint v1
```

The application calculates an HMAC-SHA1 value using the provisioned key and this message.

The first four bytes are displayed as eight hexadecimal characters.

Example:

```text
28E46ED3
```

### What is the fingerprint used for?

The fingerprint provides a convenient way to:

- Identify the currently provisioned credential.
- Check whether a recovery operation restored the expected key.
- Distinguish between different locally generated credentials.
- Display a non-secret identifier during USB discovery.

The fingerprint is not the cryptographic key.

It is only 32 bits long and should not be treated as a collision-resistant or cryptographically authenticated device identity.

[↑ Back to top](#keepass-key-for-flipper-zero)

---

## 12. Building the Flipper Application

KeePass Key is distributed as a standalone Flipper application.

It does not require a custom firmware build.

### Requirements

- Flipper Zero
- Compatible Momentum Firmware
- microSD card
- Python
- uFBT
- Windows development environment
- USB connection

### Install uFBT

uFBT provides the Flipper application build environment.

```cmd
python -m pip install --upgrade ufbt
```

### Configure the Momentum SDK

The application must be compiled against an SDK compatible with the firmware installed on the Flipper.

```cmd
ufbt update --index-url=https://up.momentum-fw.dev/firmware/directory.json
```

SDK compatibility is important because external Flipper applications depend on firmware APIs.

An incompatible application may fail to load.

### Build the application

Navigate to the project directory:

```cmd
cd keepass_key
```

Compile:

```cmd
ufbt
```

The resulting application package is:

```text
dist/keepass_key.fap
```

The `.fap` extension identifies a Flipper Application Package.

### Install the application

Connect the Flipper to a computer and open qFlipper.

Copy:

```text
keepass_key.fap
```

To:

```text
/apps/Tools/
```

The application can then be launched from the Flipper's Apps menu.

No firmware modification or boot-time installation is required.

[↑ Back to top](#keepass-key-for-flipper-zero)

---

## 13. Momentum Firmware Integration

KeePass Key can be added to Momentum Firmware's customisable main menu.

This allows the authenticator to appear alongside the Flipper's built-in applications.

The project supports a custom monochrome application icon.

Application metadata is configured in:

```text
application.fam
```

Example:

```python
App(
    appid="keepass_key",
    name="KeePass Key",
    apptype=FlipperAppType.EXTERNAL,
    entry_point="keepass_key_app",
    stack_size=4 * 1024,
    fap_category="Tools",
    fap_version="1.0",
    fap_description="KeePassXC hardware authenticator",
    fap_icon_assets="images",
    fap_icon="images/keepass_key.png",
)
```

The icon is stored at:

```text
images/keepass_key.png
```

The application remains a normal standalone `.fap` file.

Momentum's main-menu configuration provides convenient access without requiring the application to start automatically when the device boots.

[↑ Back to top](#keepass-key-for-flipper-zero)

---

## 14. Initial Setup

### Create an authentication sequence

On first launch, the application provides a sequence-creation interface.

A directional sequence between 8 and 32 inputs is configured.

The sequence should avoid predictable patterns.

It is stored locally and is not embedded in the distributed application.

### Generate the HMAC credential

The application generates a random 160-bit secret using the Flipper's hardware random-number generator.

The credential is stored in the application's persistent data directory.

### Create a recovery backup

The recovery interface allows the credential to be recorded as a 40-character hexadecimal code.

This backup is essential for recovering access after storage or hardware failure.

The recovery code should be stored separately from the Flipper.

### Verify the fingerprint

The application displays a short fingerprint derived from the provisioned key.

This can later be compared against the fingerprint of a restored credential.

[↑ Back to top](#keepass-key-for-flipper-zero)

---

## 15. Authenticating with KeePassXC

The authentication process requires a compatible modified KeePassXC build and a database configured to use the Flipper's challenge-response credential.

### Step 1 — Connect the authenticator

Connect the Flipper Zero to the computer using USB.

### Step 2 — Launch KeePass Key

Open the KeePass Key application.

The device begins in its locked state.

### Step 3 — Open KeePassXC

Open the database that requires the configured hardware authentication credential.

KeePassXC discovers the Flipper through its USB serial interface.

### Step 4 — Complete local authentication

Enter the private directional-button sequence on the Flipper.

### Step 5 — Authorise one response

Press OK to arm the authenticator.

The device is now permitted to process one valid challenge.

### Step 6 — Unlock the database

Initiate the unlock operation in KeePassXC.

KeePassXC sends the challenge to the Flipper.

The Flipper calculates the HMAC-SHA1 response and returns it.

KeePassXC uses the response during database unlocking.

### Step 7 — Automatic relocking

After the response is generated, the Flipper immediately returns to its locked state.

A subsequent authentication requires another directional sequence and explicit confirmation.

[↑ Back to top](#keepass-key-for-flipper-zero)

---

## 16. Security Architecture

KeePass Key combines several mechanisms to reduce the risks associated with an automatically accessible cryptographic credential.

| Mechanism | Security purpose |
|---|---|
| Directional authentication | Restricts access through the local interface |
| Configurable sequence length | Allows a larger authentication search space |
| Concealed input | Reduces casual observation |
| Full-sequence validation | Avoids revealing individual correct positions |
| Progressive delays | Slows repeated guessing |
| Persistent failure tracking | Preserves lockout history across application restarts |
| Hardware random-number generation | Creates unpredictable cryptographic credentials |
| HMAC-SHA1 | Produces challenge-dependent authentication responses |
| Local credential storage | Avoids transmitting the secret during normal authentication |
| Explicit confirmation | Requires deliberate permission before cryptographic use |
| Single-use authorisation | Limits each approval to one successful challenge |
| Authorisation timeout | Limits the available authentication window |
| Automatic relocking | Returns the authenticator to a restricted state |
| Protocol verification | Reduces accidental USB device misidentification |
| Input validation | Rejects malformed authentication requests |
| Recovery mechanism | Supports restoration after credential loss |

### Defence in depth

The security model does not depend on a single protective mechanism.

Physical possession, local authentication, explicit confirmation and cryptographic challenge-response each address different aspects of the authentication process.

For example, simply connecting the Flipper to a computer does not authorise the computer to request an HMAC response.

Similarly, successfully entering the directional sequence does not immediately permit unrestricted use of the cryptographic key.

A separate confirmation is required, and that authorisation is consumed after one successful operation.

[↑ Back to top](#keepass-key-for-flipper-zero)

---

## 17. Threat Model and Limitations

KeePass Key is designed to demonstrate controlled hardware-mediated authentication.

It is not intended to provide the same physical security guarantees as a dedicated hardware security module.

### Protections provided by the design

The system aims to reduce the risk of:

- Unlocking a database without access to the physical authenticator.
- Exposing the HMAC secret through normal USB authentication.
- Reusing a captured response for a different challenge.
- Performing repeated cryptographic operations after a single authorisation.
- Guessing the local sequence through the standard application interface.
- Accidentally identifying an unrelated USB device as the authenticator.

### Limitations

**No secure element**

The HMAC key is stored on removable media rather than in tamper-resistant hardware.

**Physical access to storage**

An attacker able to read or modify the microSD card may be able to extract the credential or bypass software-enforced authentication controls.

**Compromised host systems**

Malware running on the computer may interfere with authentication, use an available authorisation or access database contents after unlocking.

**Unauthenticated device discovery**

The identification protocol confirms that a device implements the expected command interface, but does not cryptographically prove possession of the HMAC credential.

**Software-enforced retry restrictions**

Progressive delays and persistent failure counters are implemented in software and can potentially be bypassed through storage manipulation.

**Recovery-path security**

Credential restoration and replacement require further review to ensure appropriate authorisation and handling of sensitive material.

**No independent security audit**

The implementation has not undergone a formal third-party security assessment.

[↑ Back to top](#keepass-key-for-flipper-zero)

---

## 18. Testing and Verification

The core system has been tested across the Flipper application, USB protocol and modified KeePassXC integration.

### Local authentication

- Directional sequence creation.
- Concealed sequence entry.
- Complete sequence validation.
- Incorrect-attempt handling.
- Progressive delays.
- Persistent failure tracking.
- Temporary authorisation.
- Manual relocking.
- Automatic timeout.

### Cryptographic functionality

- Hardware-generated HMAC credential.
- RFC 2202 HMAC-SHA1 known-answer test.
- Credential storage.
- Credential backup.
- Credential restoration.
- Fingerprint verification.
- Challenge-response calculation.

### USB communication

- Application identification.
- Non-consuming discovery.
- Challenge validation.
- Unauthorised-request rejection.
- Single-use authorisation.
- Automatic relocking.
- Error handling.

### KeePassXC integration

- USB candidate detection.
- Application protocol verification.
- Stable device identification.
- Rejection when KeePass Key is not running.
- Challenge transmission.
- Response format validation.
- Successful test database unlocking.

### Further development

Areas requiring additional work include:

- Recovery and credential-replacement hardening.
- Expanded malformed-input testing.
- Security review of credential storage.
- Firmware compatibility testing.
- Reproducible installation and deployment.
- Independent review of the KeePassXC integration.

[↑ Back to top](#keepass-key-for-flipper-zero)

---

## 19. Development Status

**Experimental — functional end-to-end prototype**

The application successfully implements the core authentication workflow.

A Flipper Zero can:

1. Generate an independent cryptographic credential.
2. Require local directional authentication.
3. Enforce progressive delays after failed attempts.
4. Require explicit permission for a cryptographic operation.
5. Receive a challenge over USB.
6. Calculate an HMAC-SHA1 response.
7. Return the response without transmitting its secret.
8. Consume the authorisation and immediately relock.

A modified KeePassXC build can discover the authenticator and use its response to unlock a test database.

The application can be built and installed independently of the firmware.

Further security review and testing are required before the project should be relied upon for production credentials.

[↑ Back to top](#keepass-key-for-flipper-zero)

---

## 20. Technical Significance

KeePass Key brings together several areas of embedded and desktop security engineering.

### Embedded cryptography

Implements HMAC-SHA1 on a microcontroller and verifies the calculation against a published test vector.

### Hardware random-number generation

Generates independent 160-bit cryptographic credentials directly on the device.

### Local authentication

Implements configurable directional authentication with concealed input, complete-sequence validation and progressive delays.

### Authentication state management

Separates locked, authorised and armed states to control access to cryptographic operations.

### Single-use permissions

Consumes authorisation after one successful challenge-response operation.

### USB protocol development

Implements a compact serial protocol with device identification, challenge processing and error handling.

### Desktop software integration

Extends KeePassXC's hardware authentication mechanism using Qt SerialPort.

### Credential lifecycle management

Supports generation, persistent storage, backup, restoration and fingerprint verification.

### Device discovery

Combines USB identification with application-level protocol verification.

### Defence in depth

Combines physical possession, local authentication, explicit confirmation and cryptographic authentication while recognising the limitations of software-controlled credential storage.

The result is a functional demonstration of hardware-mediated challenge-response authentication using a general-purpose embedded device.

[↑ Back to top](#keepass-key-for-flipper-zero)

---

## License

MIT License.
