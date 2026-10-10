KeePass Key for Flipper Zero
A hardware-based cryptographic authenticator for KeePassXC

KeePass Key transforms a Flipper Zero into a physical authentication device for KeePassXC, combining cryptographic challenge-response authentication with local access control, brute-force protection, single-use authorisation and automatic relocking.

Unlike conventional Flipper Zero password applications that use BadUSB to type stored credentials, KeePass Key never transmits its cryptographic secret during normal authentication. Instead, it calculates a unique response to a challenge supplied by KeePassXC.

Before the Flipper can perform this operation, it must be unlocked using a private directional-button sequence and explicitly authorised.

The project demonstrates how embedded cryptography, USB communication, authentication state machines and desktop application integration can be combined to create a functional hardware authentication system.

Status: Working experimental prototype. The complete authentication process has been tested successfully with a modified KeePassXC build.

Security notice: KeePass Key is an experimental project and has not undergone an independent security audit. The Flipper Zero does not provide hardware-backed secure key storage equivalent to a dedicated security token.

1. How KeePass Key Works

KeePassXC supports challenge-response authentication as an additional component of its database-unlocking process.

KeePass Key implements this functionality using a Flipper Zero connected through USB.

The authentication system combines four distinct elements:

Physical possession: The Flipper Zero must be connected to the computer.
Local authentication: A private directional-button sequence must be entered.
Explicit authorisation: A separate confirmation permits one cryptographic operation.
Cryptographic authentication: The Flipper calculates an HMAC-SHA1 response using a locally stored secret.

These elements work together to prevent the application from automatically responding to authentication requests simply because the device is connected.

Why not use BadUSB?

Many password-related Flipper applications emulate a keyboard and type a stored password.

KeePass Key uses a fundamentally different approach.

Feature	BadUSB password entry	KeePass Key
Authentication method	Keyboard emulation	Cryptographic challenge-response
Static password transmitted	Yes	No
Secret remains on device during authentication	No	Yes
Challenge-dependent response	No	Yes
Local authentication	Implementation-dependent	Required
Explicit physical confirmation	Implementation-dependent	Required
Single-use authorisation	Implementation-dependent	Yes
Automatic relocking	Implementation-dependent	Yes
KeePassXC hardware-key integration	No	Yes
Credential backup and recovery	Implementation-dependent	Yes

The fundamental difference is that KeePassXC receives the result of a cryptographic calculation rather than the secret used to produce it.

2. Understanding Challenge-Response Authentication

Challenge-response authentication allows a device to demonstrate possession of a cryptographic secret without transmitting that secret.

KeePass Key uses HMAC-SHA1, a keyed message authentication algorithm.

HMAC stands for Hash-based Message Authentication Code.

The calculation can be represented as:

Response = HMAC-SHA1(SecretKey, Challenge)

Three components are involved:

Secret key: A randomly generated 160-bit credential stored on the Flipper.
Challenge: Data supplied by KeePassXC during database unlocking.
Response: A 20-byte HMAC value calculated from the secret and challenge.
Example

KeePassXC sends a challenge:

Challenge:
A1B2C3D4E5F6...

The Flipper performs:

HMAC-SHA1(
    SecretKey,
    Challenge
)

The resulting response is returned as 40 hexadecimal characters:

OK <40 hexadecimal characters>

KeePassXC incorporates the response into its database-unlocking process.

The actual integration uses KeePassXC's challenge data and the padding required by its hardware challenge-response mechanism.

Why this is more secure than transmitting a password

The cryptographic secret is not included in the response.

An observer who captures a challenge and its corresponding response cannot directly recover the HMAC key from those values.

A response calculated for one challenge will not generally be valid for another.

Consequently, the authentication system does not depend on repeatedly transmitting a reusable password.

Why HMAC-SHA1?

HMAC-SHA1 produces a 160-bit authentication response and is compatible with the challenge-response mechanism used by KeePassXC's existing hardware-key infrastructure.

Although SHA-1 is no longer recommended for collision-resistant digital signatures, HMAC-SHA1 has different security properties because it incorporates a secret key.

The project includes a known-answer test based on RFC 2202 to verify the HMAC implementation.

3. The Complete Authentication Process

KeePass Key uses a controlled, multi-stage authentication process.

Stage 1 — USB device discovery

KeePassXC searches for compatible USB serial devices.

The expected USB vendor and product identifiers are used to identify potential Flipper devices.

However, these identifiers alone are not sufficient.

KeePassXC sends:

keepass_info

The application responds with its protocol identifier, version and key fingerprint:

OK KEEPASS_KEY 1 28E46ED3

This establishes that the connected device is responding to the KeePass Key application protocol.

Discovery does not require local authentication and does not consume an authorisation.

Stage 2 — Local authentication

The Flipper displays its locked interface.

Authentication requires a private sequence using the directional buttons:

UP
DOWN
LEFT
RIGHT

The sequence is created during initial setup.

Supported lengths range from 8 to 32 directional inputs.

The sequence is stored locally rather than embedded in the application source code.

The actual directions are concealed during entry.

Stage 3 — Sequence validation

The application validates the completed sequence.

Incorrect attempts produce a generic error without revealing which position was wrong.

Repeated failures trigger progressively longer delays.

The failure counter is stored persistently so that restarting the application does not automatically reset the attempt history.

Stage 4 — Temporary authorisation

After successful sequence validation, the Flipper enters an authorised state.

This state has a maximum duration of 30 seconds.

The device is not yet permitted to process a cryptographic challenge.

Stage 5 — Explicit confirmation

Pressing OK arms the authenticator for one challenge-response operation.

This separates local authentication from permission to use the cryptographic key.

The confirmation does not extend the original authorisation deadline.

Stage 6 — Challenge reception

KeePassXC sends a challenge through USB:

keepass_challenge <hexadecimal_challenge>

The Flipper checks that:

The challenge is present.
The hexadecimal input is valid.
The challenge length is supported.
A cryptographic key is provisioned.
The device is explicitly authorised.

Invalid requests are rejected.

Stage 7 — Cryptographic response

The Flipper calculates:

HMAC-SHA1(SecretKey, Challenge)

The resulting 20-byte response is returned to KeePassXC.

The secret key remains on the Flipper.

Stage 8 — Automatic relocking

After a successful challenge-response operation, the application immediately:

Consumes the authorisation.
Clears the authorised state.
Returns to the locked interface.

Another cryptographic operation requires the authentication sequence and confirmation to be completed again.

4. Directional Authentication

KeePass Key implements its own local authentication system using the Flipper's directional controls.

The authentication sequence is independent of the cryptographic secret.

It acts as permission to use the stored HMAC credential rather than forming part of that credential.

Configurable sequence length

Sequences can contain between 8 and 32 inputs.

Each position has four possible directions.

The theoretical number of combinations is:

4^N

Where N represents the sequence length.

Sequence length	Possible combinations
8	65,536
12	16,777,216
16	4,294,967,296
20	1,099,511,627,776
24	281,474,976,710,656
32	18,446,744,073,709,551,616

These values assume independently and uniformly selected directions.

Predictable patterns and repeated sequences can substantially reduce practical security.

Concealed input

The application does not reveal the actual directions being entered.

This reduces casual observation of the authentication sequence.

Full-sequence validation

The complete sequence is evaluated without revealing whether individual positions were correct.

An incorrect attempt displays:

Incorrect

Press OK to retry

This avoids providing position-by-position feedback that could simplify guessing.

Progressive brute-force protection

Repeated incorrect attempts trigger increasing delays.

Failed attempts	Delay
1–3	1 second
4	5 seconds
5	15 seconds
6	60 seconds
7 onwards	5 minutes

The failure counter is persisted in application storage.

Restarting the application does not simply reset the recorded failure count.

These restrictions are enforced by software and are not equivalent to hardware-enforced retry limits provided by a secure element.

5. Cryptographic Key Generation

KeePass Key generates its authentication credential directly on the Flipper Zero.

The application uses the device's hardware random-number-generation interface:

furi_hal_random_fill_buf()

This produces a randomly generated 20-byte (160-bit) HMAC key.

The key is generated independently for each installation.

It is not derived from the directional authentication sequence.

Why generate the key on-device?

Local generation avoids transmitting the credential from a computer during initial provisioning.

It also allows separate devices to generate independent cryptographic credentials.

The key is not displayed during normal provisioning.

Sensitive temporary buffers are cleared after relevant operations.

Cryptographic verification

The HMAC-SHA1 implementation includes a self-test based on RFC 2202.

The test compares a calculated HMAC against a known expected result.

This helps identify implementation errors in the cryptographic calculation.

A successful known-answer test does not, by itself, establish that the entire implementation is free from vulnerabilities.

6. Credential Storage

The HMAC credential is stored persistently in the application's dedicated microSD directory.

/ext/apps_data/keepass_key/

The credential file is:

hmac_key.bin

The application uses this credential when processing authorised challenges.

The key is not transmitted through the normal USB authentication protocol.

Physical security limitations

The Flipper Zero does not contain a dedicated secure element for protecting the HMAC credential.

The secret is stored on removable media.

An attacker with unrestricted access to the microSD card may be able to extract the credential directly.

The directional sequence restricts access through the application interface, but it does not encrypt the underlying credential file.

KeePass Key therefore provides software-controlled access to a cryptographic credential rather than hardware-enforced, non-exportable key storage.

This distinction is important when comparing the project with dedicated security tokens.

7. Single-Use Authorisation

One of KeePass Key's central security mechanisms is its single-use authorisation model.

Successful local authentication does not create an indefinitely available cryptographic service.

Instead, the application maintains separate authentication states.

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

The authorised state expires after 30 seconds.

Pressing OK arms one response without extending that deadline.

After a successful challenge, the application returns to the locked state.

Pressing BACK can also cancel authorisation and relock the device.

Why separate authentication and authorisation?

A connected computer should not automatically gain access to the cryptographic function simply because the directional sequence has been entered.

Requiring a separate confirmation introduces an additional deliberate action before the secret can be used.

Single-use authorisation also limits the number of cryptographic operations available during one successful authentication.

This reduces the opportunity for repeated requests from a connected host.

It does not, however, prevent a compromised host from attempting to use the single authorised operation.

8. USB Communication Protocol

KeePass Key communicates through the Flipper Zero's USB serial interface.

The protocol provides two primary commands.

Device identification
keepass_info

Example response:

OK KEEPASS_KEY 1 28E46ED3

The response contains:

Application identifier
Protocol version
Non-secret key fingerprint

If no credential has been provisioned:

OK KEEPASS_KEY 1 UNPROVISIONED

This command does not require local authorisation.

It also does not consume an armed challenge-response operation.

Cryptographic challenge
keepass_challenge <hexadecimal_challenge>

A successful request returns:

OK <40 hexadecimal characters>

The application validates the request before calculating the HMAC.

Supported error responses include:

ERR key_missing
ERR challenge_length
ERR invalid_hex
ERR authorization_required

The protocol rejects malformed or unauthorised requests.

After a successful response, the device immediately relocks.

Input validation

The challenge parser checks hexadecimal formatting and length.

The current protocol supports non-empty challenges up to 64 bytes.

The response is a fixed-length, 20-byte HMAC-SHA1 value encoded as 40 hexadecimal characters.

These checks prevent malformed inputs from being silently accepted as valid authentication requests.

9. KeePassXC Integration

KeePass Key includes a custom KeePassXC integration implemented using Qt 6 SerialPort.

The integration connects to KeePassXC's existing hardware challenge-response infrastructure.

Two-stage device discovery

The discovery mechanism deliberately avoids relying exclusively on USB vendor and product identifiers.

Stage 1: USB filtering

KeePassXC identifies candidate devices using the expected USB identifiers.

Stage 2: Protocol verification

Each candidate receives:

keepass_info

The integration requires a correctly formatted KeePass Key protocol response.

This reduces accidental identification of unrelated USB serial devices.

The identification response is not cryptographically authenticated and can theoretically be imitated by another device implementing the protocol.

Stable device identification

The integration derives a stable numerical identifier from USB device information.

This allows the authenticator to appear within KeePassXC's hardware-key selection interface.

Response validation

KeePassXC checks the returned challenge-response data.

The response must contain:

The expected success prefix.
Exactly 40 hexadecimal characters.
A correctly formatted 20-byte HMAC value.

Malformed responses are rejected.

Database unlocking

When a database is configured to require the Flipper authenticator, KeePassXC sends its challenge to the device.

The Flipper calculates the HMAC response.

KeePassXC incorporates that response into its normal database-unlocking process.

The Flipper does not receive the database password or database contents.

The integration requires a modified KeePassXC build. Standard KeePassXC installations do not currently include this custom Flipper interface.

10. Credential Backup and Recovery

Cryptographic challenge-response authentication depends on retaining access to the correct secret.

If the original HMAC credential is lost, a replacement device generating a different key will not reproduce the same responses.

KeePass Key therefore includes a credential backup and recovery mechanism.

Recovery code

The 160-bit HMAC key can be represented as 40 hexadecimal characters.

The application provides an authorised recovery interface for displaying this value.

Access to the backup display requires deliberate local confirmation.

The recovery display has a five-minute timeout.

Restoring a credential

The application supports manually entering an existing recovery code.

The hexadecimal input interface allows the original credential to be reconstructed.

After restoration, the application can calculate the same HMAC responses as the original installation.

This allows recovery after:

Replacing a microSD card.
Reinstalling firmware.
Reinstalling the application.
Replacing a damaged Flipper.
Restoring a previous authentication configuration.
Recovery security

The recovery code is the actual cryptographic credential represented in hexadecimal.

Anyone possessing it may be able to reproduce the authenticator's responses.

Recovery material therefore requires the same protection as the original secret.

The recovery and credential-replacement paths remain areas for additional security hardening.

11. Key Fingerprints

KeePass Key generates a short fingerprint to identify the provisioned HMAC credential.

The fingerprint is calculated using a dedicated identification message:

KeePass Key fingerprint v1

The application calculates an HMAC-SHA1 value using the provisioned key and this message.

The first four bytes are displayed as eight hexadecimal characters.

Example:

28E46ED3
What is the fingerprint used for?

The fingerprint provides a convenient way to:

Identify the currently provisioned credential.
Check whether a recovery operation restored the expected key.
Distinguish between different locally generated credentials.
Display a non-secret identifier during USB discovery.

The fingerprint is not the cryptographic key.

It is only 32 bits long and should not be treated as a collision-resistant or cryptographically authenticated device identity.

12. Building the Flipper Application

KeePass Key is distributed as a standalone Flipper application.

It does not require a custom firmware build.

Requirements
Flipper Zero
Compatible Momentum Firmware
microSD card
Python
uFBT
Windows development environment
USB connection
Install uFBT

uFBT provides the Flipper application build environment.

python -m pip install --upgrade ufbt
Configure the Momentum SDK

The application must be compiled against an SDK compatible with the firmware installed on the Flipper.

ufbt update --index-url=https://up.momentum-fw.dev/firmware/directory.json

SDK compatibility is important because external Flipper applications depend on firmware APIs.

An incompatible application may fail to load.

Build the application

Navigate to the project directory:

cd keepass_key

Compile:

ufbt

The resulting application package is:

dist/keepass_key.fap

The .fap extension identifies a Flipper Application Package.

Install the application

Connect the Flipper to a computer and open qFlipper.

Copy:

keepass_key.fap

To:

/apps/Tools/

The application can then be launched from the Flipper's Apps menu.

No firmware modification or boot-time installation is required.

13. Momentum Firmware Integration

KeePass Key can be added to Momentum Firmware's customisable main menu.

This allows the authenticator to appear alongside the Flipper's built-in applications.

The project supports a custom monochrome application icon.

Application metadata is configured in:

application.fam

Example:

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

The icon is stored at:

images/keepass_key.png

The application remains a normal standalone .fap file.

Momentum's main-menu configuration provides convenient access without requiring the application to start automatically when the device boots.

14. Initial Setup
Create an authentication sequence

On first launch, the application provides a sequence-creation interface.

A directional sequence between 8 and 32 inputs is configured.

The sequence should avoid predictable patterns.

It is stored locally and is not embedded in the distributed application.

Generate the HMAC credential

The application generates a random 160-bit secret using the Flipper's hardware random-number generator.

The credential is stored in the application's persistent data directory.

Create a recovery backup

The recovery interface allows the credential to be recorded as a 40-character hexadecimal code.

This backup is essential for recovering access after storage or hardware failure.

The recovery code should be stored separately from the Flipper.

Verify the fingerprint

The application displays a short fingerprint derived from the provisioned key.

This can later be compared against the fingerprint of a restored credential.

15. Authenticating with KeePassXC

The authentication process requires a compatible modified KeePassXC build and a database configured to use the Flipper's challenge-response credential.

Step 1 — Connect the authenticator

Connect the Flipper Zero to the computer using USB.

Step 2 — Launch KeePass Key

Open the KeePass Key application.

The device begins in its locked state.

Step 3 — Open KeePassXC

Open the database that requires the configured hardware authentication credential.

KeePassXC discovers the Flipper through its USB serial interface.

Step 4 — Complete local authentication

Enter the private directional-button sequence on the Flipper.

Step 5 — Authorise one response

Press OK to arm the authenticator.

The device is now permitted to process one valid challenge.

Step 6 — Unlock the database

Initiate the unlock operation in KeePassXC.

KeePassXC sends the challenge to the Flipper.

The Flipper calculates the HMAC-SHA1 response and returns it.

KeePassXC uses the response during database unlocking.

Step 7 — Automatic relocking

After the response is generated, the Flipper immediately returns to its locked state.

A subsequent authentication requires another directional sequence and explicit confirmation.

16. Security Architecture

KeePass Key combines several mechanisms to reduce the risks associated with an automatically accessible cryptographic credential.

Mechanism	Security purpose
Directional authentication	Restricts access through the local interface
Configurable sequence length	Allows a larger authentication search space
Concealed input	Reduces casual observation
Full-sequence validation	Avoids revealing individual correct positions
Progressive delays	Slows repeated guessing
Persistent failure tracking	Preserves lockout history across application restarts
Hardware random-number generation	Creates unpredictable cryptographic credentials
HMAC-SHA1	Produces challenge-dependent authentication responses
Local credential storage	Avoids transmitting the secret during normal authentication
Explicit confirmation	Requires deliberate permission before cryptographic use
Single-use authorisation	Limits each approval to one successful challenge
Authorisation timeout	Limits the available authentication window
Automatic relocking	Returns the authenticator to a restricted state
Protocol verification	Reduces accidental USB device misidentification
Input validation	Rejects malformed authentication requests
Recovery mechanism	Supports restoration after credential loss
Defence in depth

The security model does not depend on a single protective mechanism.

Physical possession, local authentication, explicit confirmation and cryptographic challenge-response each address different aspects of the authentication process.

For example, simply connecting the Flipper to a computer does not authorise the computer to request an HMAC response.

Similarly, successfully entering the directional sequence does not immediately permit unrestricted use of the cryptographic key.

A separate confirmation is required, and that authorisation is consumed after one successful operation.

17. Threat Model and Limitations

KeePass Key is designed to demonstrate controlled hardware-mediated authentication.

It is not intended to provide the same physical security guarantees as a dedicated hardware security module.

Protections provided by the design

The system aims to reduce the risk of:

Unlocking a database without access to the physical authenticator.
Exposing the HMAC secret through normal USB authentication.
Reusing a captured response for a different challenge.
Performing repeated cryptographic operations after a single authorisation.
Guessing the local sequence through the standard application interface.
Accidentally identifying an unrelated USB device as the authenticator.
Limitations

No secure element

The HMAC key is stored on removable media rather than in tamper-resistant hardware.

Physical access to storage

An attacker able to read or modify the microSD card may be able to extract the credential or bypass software-enforced authentication controls.

Compromised host systems

Malware running on the computer may interfere with authentication, use an available authorisation or access database contents after unlocking.

Unauthenticated device discovery

The identification protocol confirms that a device implements the expected command interface, but does not cryptographically prove possession of the HMAC credential.

Software-enforced retry restrictions

Progressive delays and persistent failure counters are implemented in software and can potentially be bypassed through storage manipulation.

Recovery-path security

Credential restoration and replacement require further review to ensure appropriate authorisation and handling of sensitive material.

No independent security audit

The implementation has not undergone a formal third-party security assessment.

18. Testing and Verification

The core system has been tested across the Flipper application, USB protocol and modified KeePassXC integration.

Local authentication
Directional sequence creation.
Concealed sequence entry.
Complete sequence validation.
Incorrect-attempt handling.
Progressive delays.
Persistent failure tracking.
Temporary authorisation.
Manual relocking.
Automatic timeout.
Cryptographic functionality
Hardware-generated HMAC credential.
RFC 2202 HMAC-SHA1 known-answer test.
Credential storage.
Credential backup.
Credential restoration.
Fingerprint verification.
Challenge-response calculation.
USB communication
Application identification.
Non-consuming discovery.
Challenge validation.
Unauthorised-request rejection.
Single-use authorisation.
Automatic relocking.
Error handling.
KeePassXC integration
USB candidate detection.
Application protocol verification.
Stable device identification.
Rejection when KeePass Key is not running.
Challenge transmission.
Response format validation.
Successful test database unlocking.
Further development

Areas requiring additional work include:

Recovery and credential-replacement hardening.
Expanded malformed-input testing.
Security review of credential storage.
Firmware compatibility testing.
Reproducible installation and deployment.
Independent review of the KeePassXC integration.
19. Development Status

Experimental — functional end-to-end prototype

The application successfully implements the core authentication workflow.

A Flipper Zero can:

Generate an independent cryptographic credential.
Require local directional authentication.
Enforce progressive delays after failed attempts.
Require explicit permission for a cryptographic operation.
Receive a challenge over USB.
Calculate an HMAC-SHA1 response.
Return the response without transmitting its secret.
Consume the authorisation and immediately relock.

A modified KeePassXC build can discover the authenticator and use its response to unlock a test database.

The application can be built and installed independently of the firmware.

Further security review and testing are required before the project should be relied upon for production credentials.

20. Technical Significance

KeePass Key brings together several areas of embedded and desktop security engineering.

Embedded cryptography

Implements HMAC-SHA1 on a microcontroller and verifies the calculation against a published test vector.

Hardware random-number generation

Generates independent 160-bit cryptographic credentials directly on the device.

Local authentication

Implements configurable directional authentication with concealed input, complete-sequence validation and progressive delays.

Authentication state management

Separates locked, authorised and armed states to control access to cryptographic operations.

Single-use permissions

Consumes authorisation after one successful challenge-response operation.

USB protocol development

Implements a compact serial protocol with device identification, challenge processing and error handling.

Desktop software integration

Extends KeePassXC's hardware authentication mechanism using Qt SerialPort.

Credential lifecycle management

Supports generation, persistent storage, backup, restoration and fingerprint verification.

Device discovery

Combines USB identification with application-level protocol verification.

Defence in depth

Combines physical possession, local authentication, explicit confirmation and cryptographic authentication while recognising the limitations of software-controlled credential storage.

The result is a functional demonstration of hardware-mediated challenge-response authentication using a general-purpose embedded device.

License

MIT License.
