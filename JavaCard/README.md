# Nostr Client with Smartcard Signing

A desktop Nostr client with HD key management and secure smartcard-based signing. The smartcard is currently simulated using JCardsim and communication is managed through TCP gateway due to unavailability of physical smartcard device.

## Overview

This application combines a Python UI for Nostr network interaction with smartcard-based private key security. It allows you to derive and manage hierarchical deterministic keys for Nostr identities while keeping private keys secure on a hardware device.

## Requirements

- Virtualbox

## Installation

1. Download https://drive.google.com/file/d/1HjxfbOTdIBNQCvl5s67BanIzgG3ryDY2/view?usp=sharing
   
2. Import into virtualbox File -> Import appliance
   
3. Login with password: "changeme"
   
4. Navigate to project directory on the desktop
   
5. In one terminal, run the Java smartcard application:
   ```bash
   java -jar smartcard_tcp_gateway.jar
   ```
6. In second terminal, run the Nostr client:
   ```bash
   python3 nostr_client_ui.py
   ```
7. The application debugging info can now be seen in the terminals

## Usage Examples

### Setting Up a New Nostr Identity

1. Launch the application
2. Click "Generate Master Key" to initialize your smartcard with a master key
3. Enter a derivation path (e.g., `m/43'/60'/1580'/0`)
4. Click "Export Public Key" to obtain your Nostr public key from
5. Your npub address is now displayed and ready to use

### Publishing a Message

1. Select one or more relays from the relay list
2. Type your message in the text area
3. Ensure your public key is exported
4. Click "Sign & Publish"
6. Check the relay connection results for publish status

### Managing HD Keys

1. Click "Extended Key Management"
2. Export an extended public key at your desired path
3. You can set an index an derive child keys from the current active parent extended public key
4. Right-click on keys in the tree view to:
   - Copy public key or npub
   - Make a key the active parent for further derivation(you can also double click)
   - Subscribe to events from a specific key
   - Remove keys from the tree(There is a bug that does not cancel subscriptions, avoid using if subscription is active)

### Following Messages

1. In Extended Key Management, right-click on keys and select "Subscribe to Events"
2. Click "Capture Messages from Subscribed Keys"
3. Messages authored by your subscribed keys will be displayed in the message log

## Security Notes

- Smartcard implementation lacks secure channel and PIN protections, I put my attention onto more functionally important parts like HKD and nostr interaction.

## Implementation details

NFC support is not implemented

Baseline for the javacard implementation was reused and inspired from [status keycard](https://github.com/OpenCryptoProject/JCMathLib) and adopted for nostr, namely implementation of Schnorr signature under javacard constraints.
[JCMathlib](https://github.com/OpenCryptoProject/JCMathLib) was used for operations with big numbers and for operations over elliptic curves.

As for the UI client, the decision to ship the project as a vm image, was due to problems being able to run it either as a docker container(desktop applications are complicated to run through there) and the nostr python package that was used in the client app is not compatible with windows. UI elements were created with the help of AI up to a minimum quality standard. 

The client app communicates with the tcp gateway by sending apdu commands which are then transfered directly onto a JCardsim runtime with keycard applet running. The responses are then trasferred back.

Line 789 derive_child_key_direct - function in client where the implementation of child key derivation from extended public keys.
