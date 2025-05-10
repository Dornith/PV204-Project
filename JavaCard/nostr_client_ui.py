import sys
import json
import time
import hashlib
import socket
import struct
import requests
import ssl
import bech32
import datetime
from nostr.event import Event, EventKind
from nostr.relay_manager import RelayManager
from nostr.message_type import ClientMessageType
from nostr.key import PrivateKey
from nostr.filter import Filter, Filters
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QTextEdit, QLineEdit, QPushButton, QLabel, QHBoxLayout, QGroupBox,
    QScrollArea, QCheckBox
)
from PySide6.QtCore import Qt


def hex_to_npub(hex_str):
    """Convert a hex public key to npub Bech32 format"""
    try:
        data = bytes.fromhex(hex_str)
        converted_bits = bech32.convertbits(data, 8, 5)
        npub = bech32.bech32_encode('npub', converted_bits)
        return npub
    except Exception as e:
        print(f"Error converting to npub: {e}")
        return None
def parse_tlv_data(tlv_data):
    """
    Parse TLV (Tag-Length-Value) data from the smartcard response
    Returns a tuple (x_coord_hex, chain_code_hex) if found, otherwise (None, None)
    """
    if not tlv_data or len(tlv_data) < 4:
        print("[ERROR] TLV data too short")
        return None, None
        
    # Check for KEY_TEMPLATE tag (0xA1)
    if tlv_data[0] != 0xA1:
        print(f"[ERROR] Invalid TLV format - missing KEY_TEMPLATE tag (expected 0xA1, got 0x{tlv_data[0]:02X})")
        return None, None
        
    # Skip outer tag and length
    offset = 2
    x_coord = None
    chain_code_hex = None
    
    while offset < len(tlv_data):
        if offset + 2 > len(tlv_data):
            print("[ERROR] Unexpected end of TLV data")
            break
            
        tag = tlv_data[offset]
        offset += 1
        length = tlv_data[offset]
        offset += 1
        
        if offset + length > len(tlv_data):
            print(f"[ERROR] Length field {length} exceeds available data")
            break
            
        if tag == 0x80:  # TLV_PUB_KEY
            public_key = tlv_data[offset:offset+length]
            
            if length >= 65:  # Ensure we have enough bytes for uncompressed key (1 + 32 + 32)
                prefix = public_key[0]
                x_coord = public_key[1:33]
                y_coord = public_key[33:65]
                
                y_is_odd = (y_coord[-1] & 0x01) == 1
                parity_prefix = b'\x03' if y_is_odd else b'\x02'
            else:
                print(f"[ERROR] Public key too short ({length} bytes)")
                
        elif tag == 0x82:  # TLV_CHAIN_CODE
            chain_code = tlv_data[offset:offset+length]
            chain_code_hex = chain_code.hex()
            
        offset += length
    
    return (x_coord.hex() if x_coord else None, chain_code_hex, parity_prefix)

def send_apdu(apdu: bytes) -> bytes:
    with socket.create_connection(('localhost', 9025), timeout=5) as s:
        s.sendall(struct.pack('>H', len(apdu)) + apdu)

        resp_len_bytes = bytearray()
        while len(resp_len_bytes) < 2:
            chunk = s.recv(2 - len(resp_len_bytes))
            if not chunk:
                raise RuntimeError(f"Socket closed before receiving full length prefix ({len(resp_len_bytes)}/2)")
            resp_len_bytes.extend(chunk)

        resp_len = struct.unpack('>H', resp_len_bytes)[0]

        # Now read exactly resp_len bytes
        response = bytearray()
        while len(response) < resp_len:
            chunk = s.recv(resp_len - len(response))
            if not chunk:
                raise RuntimeError(f"Socket closed before receiving full response ({len(response)}/{resp_len})")
            response.extend(chunk)

        return bytes(response)

class NostrClientUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Nostr Client with Smartcard Signing")
        self.pubkey_hex = None
        self.chain_code = None
        self.parity_prefix = None
        self.subs_list = {}
        
        # Initialize dialog-related attributes
        self.key_dialog = None
        self.derived_keys = {}
        self.active_parent = {
            "pubkey": None,
            "chain_code": None,
            "parity": None,
            "path": None
        }
        
        self._setup_ui()

    def _setup_ui(self):
        central = QWidget()
        layout = QVBoxLayout(central)

        # Relay selection group
        relay_group = QGroupBox("Relay Selection")
        relay_layout = QVBoxLayout(relay_group)
        
        # Predefined relay URLs
        self.relay_urls = [
            "wss://nos.lol/",
            "wss://nostr.land/",
            "wss://nostr.wine/",
            "wss://purplepag.es/",
            "wss://purplerelay.com/",
            "wss://relay.damus.io/",
            "wss://relay.snort.social/"
        ]
        
        # Create checkboxes for each relay
        self.relay_checkboxes = []
        for url in self.relay_urls:
            checkbox = QCheckBox(url)
            relay_layout.addWidget(checkbox)
            self.relay_checkboxes.append(checkbox)
        
        # Set the three checked by default
        if self.relay_checkboxes:
            self.relay_checkboxes[0].setChecked(True)
            self.relay_checkboxes[1].setChecked(True)
            self.relay_checkboxes[2].setChecked(True)
        
        # Make the relay section scrollable if needed
        scroll_area = QScrollArea()
        scroll_area.setWidget(relay_group)
        scroll_area.setWidgetResizable(True)
        scroll_area.setMaximumHeight(150)
        layout.addWidget(scroll_area)

        # Derivation path input
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("Derivation Path:"))
        self.path_input = QLineEdit("m/43'/60'/1580'/0")
        self.path_input.setToolTip("Format: m/a'/b'/c'/d/e - Use ' for hardened paths")
        path_layout.addWidget(self.path_input)
        layout.addLayout(path_layout)

        # Message input
        layout.addWidget(QLabel("Message:"))
        self.msg_edit = QTextEdit()
        layout.addWidget(self.msg_edit)

        # Sign & publish button
        self.send_btn = QPushButton("Sign & Publish")
        self.send_btn.clicked.connect(self.sign_and_publish)
        layout.addWidget(self.send_btn)
        
        # Generate master key button
        self.gen_key_btn = QPushButton("Generate Master Key")
        self.gen_key_btn.clicked.connect(self.generate_master_key)
        layout.addWidget(self.gen_key_btn)

        # Export public key button
        self.export_pubkey_btn = QPushButton("Export Public Key")
        self.export_pubkey_btn.clicked.connect(self.export_public_key)
        layout.addWidget(self.export_pubkey_btn)

        # Public key display
        self.pubkey_label = QLabel("Public Key: Not exported yet")
        self.pubkey_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.pubkey_label)

        # Relay connection results
        layout.addWidget(QLabel("Relay Connection Results:"))
        self.relay_results = QTextEdit()
        self.relay_results.setReadOnly(True)
        self.relay_results.setMaximumHeight(100)
        layout.addWidget(self.relay_results)

        # Key management button
        self.key_management_btn = QPushButton("Extended Key Management")
        self.key_management_btn.clicked.connect(self.explore_child_keys)
        self.key_management_btn.setToolTip("Manage extended public keys and derive child keys")
        layout.addWidget(self.key_management_btn)
        
        # Status label
        self.status = QLabel("")
        self.status.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status)

        self.setCentralWidget(central)


    def parse_derivation_path(self, path_str):
        if path_str.startswith('m/'):
            path_str = path_str[2:]
        
        components = path_str.split('/')
        result = bytearray()
        
        for component in components:
            is_hardened = component.endswith("'")
            if is_hardened:
                component = component[:-1]
            
            index = int(component)
            if is_hardened:
                index |= 0x80000000
            
            result.extend(index.to_bytes(4, 'big'))
        
        return bytes(result)


    def export_public_key(self):
        try:
            path_str = self.path_input.text().strip()
            path_bytes = self.parse_derivation_path(path_str)
            apdu = bytes.fromhex("B0900201") + len(path_bytes).to_bytes(1, 'big') + path_bytes
            
            response = send_apdu(apdu)
            
            if len(response) >= 2:
                data, sw1, sw2 = response[:-2], response[-2], response[-1]
                print(f"[RESULT] Response: {data.hex()}   SW1SW2: {sw1:02X}{sw2:02X}")
                
                if (sw1, sw2) == (0x90, 0x00):
                    x_coord_hex, chain_code_hex, parity_prefix = parse_tlv_data(data)
                    if x_coord_hex:
                        self.pubkey_hex = x_coord_hex
                        self.parity_prefix = parity_prefix
                        if chain_code_hex:
                            self.chain_code = chain_code_hex
                        npub = hex_to_npub(x_coord_hex)
                        if npub:
                            self.pubkey_label.setText(f"Current Public Key: {npub}")
                        else:
                            self.pubkey_label.setText(f"Current Public Key: {self.pubkey_hex}")
                        self.status.setText(f"Public key exported successfully")
                    else:
                        self.status.setText("Failed to extract public key from TLV data")
                else:
                    self.status.setText(f"Card error: {sw1:02X}{sw2:02X}")
            else:
                print(f"[ERROR] Response too short to contain SW1/SW2: {response.hex()}", file=sys.stderr)
                self.status.setText("Invalid response from card")
        except Exception as e:
            print(f"[ERROR] Export public key failed: {e}", file=sys.stderr)
            self.status.setText(f"Export public key failed: {str(e)}")

    def export_extended_public_key(self):
        try:
            path_str = self.path_input.text().strip()
            path_bytes = self.parse_derivation_path(path_str)
            apdu = bytes.fromhex("B0900202") + len(path_bytes).to_bytes(1, 'big') + path_bytes
            
            response = send_apdu(apdu)
            
            if len(response) >= 2:
                data, sw1, sw2 = response[:-2], response[-2], response[-1]
                print(f"[RESULT] Response: {data.hex()}   SW1SW2: {sw1:02X}{sw2:02X}")
                
                if (sw1, sw2) == (0x90, 0x00):
                    x_coord_hex, chain_code_hex = parse_tlv_data(data)
                    if x_coord_hex:
                        self.pubkey_hex = x_coord_hex
                        if chain_code_hex:
                            self.chain_code = chain_code_hex
                        npub = hex_to_npub(x_coord_hex)
                        if npub:
                            self.pubkey_label.setText(f"Current Public Key: {npub}")
                        else:
                            # Fallback to hex if bech32 encoding fails
                            self.pubkey_label.setText(f"Current Public Key: {self.pubkey_hex}")
                        self.status.setText(f"Public key exported successfully")
                    else:
                        self.status.setText("Failed to extract public key from TLV data")
                else:
                    self.status.setText(f"Card error: {sw1:02X}{sw2:02X}")
            else:
                print(f"[ERROR] Response too short to contain SW1/SW2: {response.hex()}", file=sys.stderr)
                self.status.setText("Invalid response from card")
        except Exception as e:
            print(f"[ERROR] Export public key failed: {e}", file=sys.stderr)
            self.status.setText(f"Export public key failed: {str(e)}")
    def generate_master_key(self):
        try:
            apdu = bytes.fromhex("B0D40000")
            self.status.setText("Generating master key...")
            
            response = send_apdu(apdu)
            
            if len(response) >= 2:
                data, sw1, sw2 = response[:-2], response[-2], response[-1]
                print(f"[RESULT] Data: {data.hex()}   SW1SW2: {sw1:02X}{sw2:02X}")
                
                if (sw1, sw2) == (0x90, 0x00):
                    self.status.setText("Master key generated successfully!")
                else:
                    self.status.setText(f"Card error: {sw1:02X}{sw2:02X}")
            else:
                print(f"[ERROR] Response too short to contain SW1/SW2: {response.hex()}", file=sys.stderr)
                self.status.setText("Invalid response from card")
        except Exception as e:
            print(f"[ERROR] Generate master key failed: {e}", file=sys.stderr)
            self.status.setText(f"Generate master key failed: {str(e)}")


    def sign_and_publish(self):
        self.relay_results.clear()
        self.send_btn.setEnabled(False)
        self.status.setText("Preparing to sign and publish...")
        QApplication.processEvents()
        msg = self.msg_edit.toPlainText().strip()
        path_str = self.path_input.text().strip()
        selected_relays = [cb.text() for cb in self.relay_checkboxes if cb.isChecked()]
        
        try:
            if not selected_relays:
                self.status.setText("Please select at least one relay.")
                return
            if not msg:
                self.status.setText("Please enter a message.")
                return
            if not self.pubkey_hex:
                self.status.setText("Please export your public key first.")
                return
            
            try:
                path_bytes = self.parse_derivation_path(path_str)
            except Exception as e:
                self.status.setText(f"Invalid derivation path: {str(e)}")
                return

            # Define event parameters following Nostr spec
            created_at = int(time.time())
            event_params = {
                "pubkey": self.pubkey_hex,
                "created_at": created_at,
                "kind": EventKind.TEXT_NOTE,
                "tags": [],
                "content": msg
            }

            QApplication.processEvents()
            payload = [
                0,
                event_params["pubkey"],
                event_params["created_at"],
                event_params["kind"],
                event_params["tags"],
                event_params["content"]
            ]
            serialized = json.dumps(payload, separators=(',', ':'), ensure_ascii=False)
            event_id = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
            event_params["id"] = event_id
            
            data = bytes.fromhex(event_id) + path_bytes
            self.status.setText(f"Signing message with path: {path_str}")
            apdu = bytes.fromhex("B0C00200") + len(data).to_bytes(1, 'big') + data
            
            try:
                response = send_apdu(apdu)
            except Exception as e:
                print(f"[ERROR] send_apdu failed: {e}", file=sys.stderr)
                self.status.setText(f"Signing failed: {str(e)}")
                return

            if len(response) >= 2:
                sig, sw1, sw2 = response[:-2], response[-2], response[-1]
                print(f"[RESULT] Signature: {sig.hex()}   SW1SW2: {sw1:02X}{sw2:02X}")
                
                if (sw1, sw2) != (0x90, 0x00):
                    self.status.setText(f"Card error: {sw1:02X}{sw2:02X}")
                    return
                    
                event_params["sig"] = sig.hex()
                
                event = Event(
                    public_key=event_params["pubkey"],
                    created_at=event_params["created_at"],
                    kind=event_params["kind"],
                    tags=event_params["tags"],
                    content=event_params["content"],
                    id=event_params["id"],
                    signature=event_params["sig"]
                )
                
                if not event.verify():
                    self.status.setText("Event verification failed. Not sending.")
                    return
                
                success_relays = []
                failed_relays = []
                
                self.relay_results.clear()
                self.relay_results.setText(f"Attempting to publish to {len(selected_relays)} relays...\n")
                
                for idx, relay_url in enumerate(selected_relays):
                    self.relay_results.append(f"Connecting to {relay_url}...")
                    self.status.setText(f"Publishing to relay {idx+1}/{len(selected_relays)}: {relay_url}")
                    QApplication.processEvents()
                    try:
                        relay_manager = RelayManager()
                        relay_manager.add_relay(relay_url)
                        
                        relay_manager.open_connections({"cert_reqs": ssl.CERT_NONE})
                        time.sleep(0.5)  # Brief wait for connection
                        
                        relay_manager.publish_event(event)
                        
                        relay_manager.close_connections()
                        
                        success_relays.append(relay_url)
                        self.relay_results.undo()
                        self.relay_results.append(f"✅ {relay_url}")
                        QApplication.processEvents()
                        print(f"[SUCCESS] Published to {relay_url}")
                        
                    except Exception as e:
                        failed_relays.append(relay_url)
                        self.relay_results.undo()  # Remove the "Connecting..." line
                        self.relay_results.append(f"❌ {relay_url} - {str(e)}")
                        print(f"[ERROR] Failed to publish to {relay_url}: {str(e)}")

                if success_relays:
                    success_msg = f"Published to {len(success_relays)}/{len(selected_relays)} relays"
                    if failed_relays:
                        self.status.setText(f"{success_msg}. See details below.")
                    else:
                        self.status.setText(f"{success_msg} successfully!")
                else:
                    self.status.setText("Failed to publish to all selected relays.")
            else:
                print(f"[ERROR] Response too short to contain SW1/SW2: {response.hex()}", file=sys.stderr)
                self.status.setText("Invalid response from card")
        
        finally:
            self.send_btn.setEnabled(True)

    def capture_messages(self):
        selected_relays = [cb.text() for cb in self.relay_checkboxes if cb.isChecked()]
        if not selected_relays:
            self.message_log.setText("Please select at least one relay to capture messages from.")
            return
        if self.subs_list.keys() == []:
            self.message_log.setText("Please subscribe to at least one key first.")
            return
        
        self.message_log.clear()
        self.message_log.append(f"Connecting to selected {len(selected_relays)} relays...")
        QApplication.processEvents()
        
        relay_manager = RelayManager()
        for relay_url in selected_relays:
            relay_manager.add_relay(relay_url)
        
        try:
            pubkey_list = list(self.subs_list.keys())
            
            if not pubkey_list:
                self.message_log.append("No subscribed keys. Please subscribe to at least one key first.")
                return
            
            subscription_id = "user_subscription"
            filters = Filters([
                Filter(authors=pubkey_list, kinds=[EventKind.TEXT_NOTE])
            ])
            
            relay_manager.add_subscription(subscription_id, filters)
            relay_manager.open_connections({"cert_reqs": ssl.CERT_NONE})
            
            self.message_log.append("Connected to relays")
            self.message_log.append(f"Listening for {len(pubkey_list)} pubkeys")
            
            self.message_log.append("Subscribed to keys:")
            for pubkey in pubkey_list[:5]:  # Limit to first 5 for readability
                npub = hex_to_npub(pubkey)
                self.message_log.append(f"  {npub if npub else pubkey}")
            if len(pubkey_list) > 5:
                self.message_log.append(f"  ... and {len(pubkey_list) - 5} more")
            
            time.sleep(1)  
            QApplication.processEvents()
            
            request = [ClientMessageType.REQUEST, subscription_id]
            request.extend(filters.to_json_array())
            message = json.dumps(request)
            relay_manager.publish_message(message)
            
            self.message_log.append("Waiting for events...")
            QApplication.processEvents()
            time.sleep(2) 
            
            event_list = []
            while relay_manager.message_pool.has_events():
                event_msg = relay_manager.message_pool.get_event()
                if event_msg and hasattr(event_msg, 'event'):
                    event_list.append(event_msg.event)
            
            event_list.sort(key=lambda e: e.created_at, reverse=True)
            
            if len(event_list) == 0:
                self.message_log.append("No events found.")
            else:
                self.message_log.append(f"Found {len(event_list)} events:")
                for event in event_list:
                    self.message_log.append(f"Event ID: {event.id}")
                    self.message_log.append(f"Pubkey: {hex_to_npub(event.public_key)}")
                    content = event.content
                    self.message_log.append(f"Content: {content}")
                    
                    self.message_log.append(f"Created At: {datetime.datetime.fromtimestamp(event.created_at).strftime('%Y-%m-%d %H:%M:%S')}")
                    self.message_log.append("-" * 40)
                    QApplication.processEvents()
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.message_log.append(f"Error: {str(e)}")
        finally:
            try:
                relay_manager.close_connections()
                self.message_log.append("Connections closed.")
            except:
                pass
    def explore_child_keys(self):
        from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, QSpinBox, 
                                    QPushButton, QTextEdit, QGroupBox, QTreeWidget, 
                                    QTreeWidgetItem, QSplitter, QMenu, QLineEdit)
        from PySide6.QtCore import Qt, QSize
        from PySide6.QtGui import QAction
        
        if self.key_dialog:
            if hasattr(self, 'dialog_path_input'):
                self.dialog_path_input.setText(self.path_input.text())
            self.key_dialog.show()
            return
            
        dialog = QDialog(self)
        dialog.setWindowTitle("Extended Key Management")
        dialog.setModal(False)  # Explicitly set as non-modal
        layout = QVBoxLayout(dialog)
        
        self.key_dialog = dialog
        
        # Extended public key export group
        export_group = QGroupBox("Extended Public Key")
        export_layout = QVBoxLayout(export_group)
        
        # Path input in dialog (duplicating the main window's path input)
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("Derivation Path:"))
        self.dialog_path_input = QLineEdit(self.path_input.text())
        self.dialog_path_input.setToolTip("Format: m/a'/b'/c'/d/e - Use ' for hardened paths")
        path_layout.addWidget(self.dialog_path_input)
        export_layout.addLayout(path_layout)
        
        # Key info display
        self.key_info_label = QLabel("No public key available")
        self.chain_info_label = QLabel("No chain code available")
        self.prefix_info_label = QLabel("No prefix available")

        self.key_info_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.chain_info_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.prefix_info_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.key_info_label.setWordWrap(True)
        self.chain_info_label.setWordWrap(True)
        self.prefix_info_label.setWordWrap(True)
        export_layout.addWidget(self.key_info_label)
        export_layout.addWidget(self.chain_info_label)
        export_layout.addWidget(self.prefix_info_label)
        
        # Function to update the UI with current key information
        def update_key_display():
            if self.pubkey_hex and self.chain_code:
                self.key_info_label.setText(f"Current Public Key: {self.pubkey_hex}")
                self.chain_info_label.setText(f"Current Chain Code: {self.chain_code}")
                self.prefix_info_label.setText(f"Current Parity Prefix: {self.parity_prefix.hex() if self.parity_prefix else 'None'}")
                
                # Show derivation group if not already shown
                if not derive_group.isVisible() and self.pubkey_hex and self.chain_code:
                    messages_group.setVisible(True)
                    derive_group.setVisible(True)
                    
                # Add parent key to tree if it doesn't exist
                add_parent_key_to_tree()
            else:
                self.key_info_label.setText("No public key available")
                self.chain_info_label.setText("No chain code available")
                self.prefix_info_label.setText("No prefix available")
        
        # Export extended public key button
        export_extended_btn = QPushButton("Export Extended Public Key")
        export_extended_btn.setToolTip("Export extended public key for current derivation path")
        export_layout.addWidget(export_extended_btn)
        
        self.extended_status = QLabel("")
        self.extended_status.setAlignment(Qt.AlignCenter)
        export_layout.addWidget(self.extended_status)
        
        original_status_setter = self.status.setText
        def update_both_status(text):
            original_status_setter(text)
            self.extended_status.setText(text)
        self.status.setText = update_both_status
        
        layout.addWidget(export_group)
        
        derive_group = QGroupBox("Key Hierarchy")
        derive_layout = QVBoxLayout(derive_group)
        
        splitter = QSplitter(Qt.Vertical)
        
        derivation_widget = QWidget()
        derivation_layout = QVBoxLayout(derivation_widget)
        
        self.active_key_label = QLabel("Active Parent: (None)")
        self.active_key_label.setWordWrap(True)
        derivation_layout.addWidget(self.active_key_label)
        
        def update_active_parent():
            if self.active_parent["pubkey"]:
                path = self.active_parent.get("path", "Unknown Path")
                self.active_key_label.setText(f"Active Parent: {path}")
            else:
                self.active_key_label.setText("Active Parent: (None)")
        
        index_layout = QHBoxLayout()
        index_layout.addWidget(QLabel("Derivation Index:"))
        index_spinner = QSpinBox()
        index_spinner.setRange(0, 0x7FFFFFFF)  # Max non-hardened index
        index_spinner.setValue(0)
        index_layout.addWidget(index_spinner)
        derive_button = QPushButton("Derive Child Key")
        index_layout.addWidget(derive_button)
        derivation_layout.addLayout(index_layout)
        
        splitter.addWidget(derivation_widget)
        
        self.key_tree = QTreeWidget()
        self.key_tree.setHeaderLabels(["Key Path", "Public Key (NPUB)", "Status"])
        self.key_tree.setColumnWidth(0, 180)
        self.key_tree.setColumnWidth(1, 350)
        
        splitter.addWidget(self.key_tree)
        
        derive_layout.addWidget(splitter)
        
        messages_group = QGroupBox("Message Log")
        messages_layout = QVBoxLayout(messages_group)
        
        capture_btn = QPushButton("Capture Messages from Subscribed Keys")
        capture_btn.clicked.connect(self.capture_messages)
        capture_btn.setToolTip("Fetch recent messages from relays for all subscribed keys")
        messages_layout.addWidget(capture_btn)
        
        self.message_log = QTextEdit()
        self.message_log.setReadOnly(True)
        self.message_log.setMinimumHeight(150)
        self.message_log.setPlaceholderText("Messages from subscribed keys will appear here")
        messages_layout.addWidget(self.message_log)
        
        layout.addWidget(derive_group)
        layout.addWidget(messages_group)
        
        derive_group.setVisible(bool(self.pubkey_hex and self.chain_code))
        messages_group.setVisible(bool(self.pubkey_hex and self.chain_code))

        def add_parent_key_to_tree():
            if self.pubkey_hex in self.derived_keys:
                return
                
            path_str = self.dialog_path_input.text().strip()
            parent_item = QTreeWidgetItem(self.key_tree)
            parent_item.setText(0, path_str)
            
            npub = hex_to_npub(self.pubkey_hex)
            display_key = npub if npub else self.pubkey_hex
            parent_item.setText(1, display_key)
            parent_item.setText(2, "Not Subscribed")
            
            self.derived_keys[self.pubkey_hex] = {
                "item": parent_item,
                "path": path_str,
                "pubkey": self.pubkey_hex,
                "chain_code": self.chain_code,
                "npub": npub,
                "parity_prefix": self.parity_prefix,
            }

            self.active_parent["pubkey"] = self.pubkey_hex
            self.active_parent["chain_code"] = self.chain_code
            self.active_parent["path"] = path_str
            self.active_parent["parity"] = self.parity_prefix
            update_active_parent()
            
            parent_item.setExpanded(True)
        
        def add_child_key_to_tree(parent_pubkey, index, child_pubkey, child_chain_code, child_parity_prefix):
            parent_data = self.derived_keys.get(parent_pubkey)
            if not parent_data:
                parent_item = self.key_tree.invisibleRootItem()
                parent_path = self.dialog_path_input.text().strip()
            else:
                parent_item = parent_data["item"]
                parent_path = parent_data["path"]
            
            child_path = f"{parent_path}/{index}"
            
            if child_pubkey in self.derived_keys:
                return self.derived_keys[child_pubkey]["item"]
            
            child_item = QTreeWidgetItem(parent_item)
            child_item.setText(0, child_path)
            
            npub = hex_to_npub(child_pubkey)
            display_key = npub if npub else child_pubkey
            child_item.setText(1, display_key)
            child_item.setText(2, "Not Subscribed")

            self.derived_keys[child_pubkey] = {
                "item": child_item,
                "path": child_path,
                "pubkey": child_pubkey,
                "chain_code": child_chain_code,
                "npub": npub,
                "parent": parent_pubkey,
                "index": index,
                "parity_prefix": child_parity_prefix
            }
            
            return child_item
        
        def on_derive():
            index = index_spinner.value()
            
            parent_pubkey = self.active_parent.get("pubkey")
            parent_chain_code = self.active_parent.get("chain_code")
            
            if not parent_pubkey or not parent_chain_code:
                self.extended_status.setText("No parent key available. Export extended public key first.")
                return
            
            self.extended_status.setText(f"Deriving child key at index: {index}...")

            child_key = derive_child_key_direct(parent_pubkey, parent_chain_code, index)
            
            if child_key:
                child_pubkey, child_chain_code, parity_prefix = child_key
                print(f"[DEBUG] Derived child key: {child_pubkey}, chain code: {child_chain_code}, parity prefix: {parity_prefix.hex()}")
                child_item = add_child_key_to_tree(parent_pubkey, index, child_pubkey, child_chain_code, parity_prefix)
                self.key_tree.setCurrentItem(child_item)
                self.extended_status.setText(f"Successfully derived child key at index {index}")
            else:
                self.extended_status.setText("Derivation failed")

        def derive_child_key_direct(parent_pubkey_hex, parent_chain_code_hex, index):
            import hashlib
            import hmac
            
            if index >= 0x80000000:
                self.extended_status.setText("Cannot derive hardened children (index >= 2^31) from public key.")
                return None
            
            try:
                try:
                    from coincurve import PublicKey
                except ImportError:
                    self.extended_status.setText("Please install coincurve: pip install coincurve")
                    return None
                
                if len(parent_pubkey_hex) == 64:
                    parent_pubkey_bytes = bytes.fromhex(parent_pubkey_hex)
                    
                    parent_data = self.derived_keys.get(parent_pubkey_hex, {})
                    parent_parity = parent_data.get("parity_prefix", None)
                    
                    prefix = parent_parity if isinstance(parent_parity, bytes) else bytes.fromhex(parent_parity)
                    try:
                        pubkey_obj = PublicKey(prefix + parent_pubkey_bytes)
                        parent_pubkey_bytes = pubkey_obj.format(compressed=True)
                    except Exception as e1:
                        print(f"[ERROR] Failed with stored parity ({prefix.hex()}): {e1}")
                        # Try alternative prefix as fallback
                        alt_prefix = b'\x02' if prefix == b'\x03' else b'\x03'
                        try:
                            pubkey_obj = PublicKey(alt_prefix + parent_pubkey_bytes)
                            parent_pubkey_bytes = pubkey_obj.format(compressed=True)
                        except Exception as e2:
                            print(f"[ERROR] Both prefixes failed: {e1}, {e2}")
                            return None
                try:
                    chain_code = bytes.fromhex(parent_chain_code_hex)
                except Exception as e:
                    print(f"[ERROR] Failed to parse chain code: {e}")
                    self.extended_status.setText(f"Invalid chain code format: {str(e)}")
                    return None
                
                try:
                    parent_pubkey = PublicKey(parent_pubkey_bytes)
                except Exception as e:
                    print(f"[ERROR] Failed to create PublicKey object: {e}")
                    self.extended_status.setText(f"Invalid public key: {str(e)}")
                    return None
                
                data = parent_pubkey.format(compressed=True) + index.to_bytes(4, byteorder='big')
                
                h = hmac.new(chain_code, data, hashlib.sha512).digest()
                
                IL, IR = h[:32], h[32:]
                
                child_chain_code = IR.hex()
                
                curve_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
                IL_int = int.from_bytes(IL, byteorder='big')
                
                if IL_int >= curve_order:
                    print(f"[ERROR] IL value {IL_int} is >= curve order {curve_order}")
                    self.extended_status.setText("Derivation failed: IL is not a valid scalar. Try next index.")
                    return None
                
                try:
                    child_pubkey = parent_pubkey.add(IL)
                except Exception as e:
                    print(f"[ERROR] Failed to add scalar to parent key: {e}")
                    self.extended_status.setText(f"Key addition failed: {str(e)}")
                    return None
                
                try:
                    child_pubkey_bytes = child_pubkey.format(compressed=True)
                except Exception as e:
                    print(f"[ERROR] Failed to format child pubkey: {e}")
                    self.extended_status.setText(f"Key formatting failed: {str(e)}")
                    return None
                
                if child_pubkey_bytes == bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"):
                    print("[ERROR] Child public key is the point at infinity")
                    self.extended_status.setText("Derivation failed: result is point at infinity. Try next index.")
                    return None
                
                # For Nostr, we just want the x-coordinate (32 bytes)
                child_pubkey_x = child_pubkey_bytes[1:33].hex()
                parity_prefix = child_pubkey_bytes[:1]
                print(f"[DEBUG] Child pubkey x-coordinate: {child_pubkey_x}")
                
                self.extended_status.setText(f"Successfully derived child key at index {index}")
                return (child_pubkey_x, child_chain_code, parity_prefix)
                    
            except Exception as e:
                import traceback
                traceback.print_exc()
                print(f"[ERROR] Unexpected exception in derivation: {e}")
                self.extended_status.setText(f"Derivation error: {str(e)}")
                return None
        def make_active_parent(pubkey):
            if pubkey not in self.derived_keys:
                self.extended_status.setText("Error: Key not found in derived keys")
                return
                
            data = self.derived_keys[pubkey]
            
            self.dialog_path_input.setText(data["path"])
            self.chain_info_label.setText(f"Current Chain Code: {data['chain_code']}")
            self.key_info_label.setText(f"Current Public Key: {pubkey}")
            self.prefix_info_label.setText(f"Current Parity Prefix: {data['parity_prefix'].hex() if data['parity_prefix'] else 'None'}")
            self.pubkey_hex = pubkey
            self.chain_code = data["chain_code"]
            npub = hex_to_npub(pubkey)
            if npub:
                self.pubkey_label.setText(f"Current Public Key: {npub}")
            else:
                self.pubkey_label.setText(f"Current Public Key: {self.pubkey_hex}")
            self.status.setText(f"Public key exported successfully")
            self.active_parent["pubkey"] = pubkey
            self.active_parent["chain_code"] = data["chain_code"]
            self.active_parent["path"] = data["path"]
            self.active_parent["parity"] = data["parity_prefix"]
            
            update_active_parent()
            QApplication.processEvents()
            self.extended_status.setText(f"Made {data['path']} the active parent for derivation")
        
        def remove_key(pubkey):
            if pubkey not in self.derived_keys:
                return
                
            children_to_remove = []
            
            def find_children(parent_key):
                children = []
                for key, data in self.derived_keys.items():
                    if data.get("parent") == parent_key:
                        children.append(key)
                        children.extend(find_children(key))
                return children
            
            children_to_remove = find_children(pubkey)
            
            for child_key in reversed(children_to_remove):
                if child_key in self.derived_keys:
                    child_data = self.derived_keys[child_key]
                    child_item = child_data["item"]
                    parent_item = child_item.parent()
                    if parent_item:
                        parent_item.removeChild(child_item)
                    del self.derived_keys[child_key]
                    
                    # Reset active parent if it was this key
                    if self.active_parent["pubkey"] == child_key:
                        self.active_parent["pubkey"] = None
                        self.active_parent["chain_code"] = None
                        self.active_parent["path"] = None
                        update_active_parent()
            
            key_data = self.derived_keys[pubkey]
            key_item = key_data["item"]
            parent_item = key_item.parent()
            
            if parent_item:
                parent_item.removeChild(key_item)
            else:
                root = self.key_tree.invisibleRootItem()
                for i in range(root.childCount()):
                    if root.child(i) == key_item:
                        root.takeChild(i)
                        break
            
            del self.derived_keys[pubkey]
            
            if self.active_parent["pubkey"] == pubkey:
                self.active_parent["pubkey"] = None
                self.active_parent["chain_code"] = None
                self.active_parent["path"] = None
                update_active_parent()
                
            self.extended_status.setText(f"Removed key {key_data['path']} and its descendants")
        
        def show_tree_context_menu(position):
            item = self.key_tree.itemAt(position)
            if not item:
                return
                
            pubkey = None
            for key, data in self.derived_keys.items():
                if data["item"] == item:
                    pubkey = key
                    break
                    
            if not pubkey:
                return
                    
            menu = QMenu()
            
            copy_action = QAction("Copy Public Key (hex)", dialog)
            copy_action.triggered.connect(lambda: QApplication.clipboard().setText(pubkey))
            menu.addAction(copy_action)
            
            npub = self.derived_keys[pubkey].get("npub")
            if npub:
                copy_npub_action = QAction("Copy NPUB", dialog)
                copy_npub_action.triggered.connect(lambda: QApplication.clipboard().setText(npub))
                menu.addAction(copy_npub_action)
            
            make_parent_action = QAction("Make Active Parent", dialog)
            make_parent_action.triggered.connect(lambda: make_active_parent(pubkey))
            menu.addAction(make_parent_action)
            
            remove_action = QAction("Remove Key", dialog)
            remove_action.triggered.connect(lambda: remove_key(pubkey))
            menu.addAction(remove_action)
            
            menu.addSeparator()
            
            subscribe_action = QAction("Subscribe to Events", dialog)
            subscribe_action.triggered.connect(lambda: toggle_subscription(pubkey))
            menu.addAction(subscribe_action)
            
            menu.exec_(self.key_tree.viewport().mapToGlobal(position))
        
        def on_tree_double_click(item, column):
            pubkey = None
            for key, data in self.derived_keys.items():
                if data["item"] == item:
                    pubkey = key
                    break
                    
            if pubkey:
                make_active_parent(pubkey)
        
        def toggle_subscription(pubkey):
            data = self.derived_keys[pubkey]
            item = data["item"]
            if item.text(2) == "Subscribed":
                self.subs_list.pop(pubkey, None)
                item.setText(2, "Not Subscribed")
                self.extended_status.setText(f"Unsubscribed from {data['path']}")
            else:
                self.subs_list[pubkey] = data
                item.setText(2, "Subscribed")
                self.extended_status.setText(f"Subscribed to {data['path']}")
        
        derive_button.clicked.connect(on_derive)
        self.key_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.key_tree.customContextMenuRequested.connect(show_tree_context_menu)
        self.key_tree.itemDoubleClicked.connect(on_tree_double_click)
        
        splitter.addWidget(self.key_tree)
        
        derive_layout.addWidget(splitter)
        
        layout.addWidget(derive_group)
        derive_group.setVisible(bool(self.pubkey_hex and self.chain_code))
        
        def dialog_export_extended_public_key():
            try:
                path_str = self.dialog_path_input.text().strip()
                path_bytes = self.parse_derivation_path(path_str)
                apdu = bytes.fromhex("B0900202") + len(path_bytes).to_bytes(1, 'big') + path_bytes
                
                response = send_apdu(apdu)
                
                if len(response) >= 2:
                    data, sw1, sw2 = response[:-2], response[-2], response[-1]
                    print(f"[RESULT] Response: {data.hex()}   SW1SW2: {sw1:02X}{sw2:02X}")
                    
                    if (sw1, sw2) == (0x90, 0x00):
                        x_coord_hex, chain_code_hex, parity_prefix = parse_tlv_data(data)
                        self.parity_prefix = parity_prefix
                        self.path_input.setText(path_str)
                        if x_coord_hex:
                            self.pubkey_hex = x_coord_hex
                            if chain_code_hex:
                                self.chain_code = chain_code_hex
                            npub = hex_to_npub(x_coord_hex)
                            if npub:
                                self.pubkey_label.setText(f"Current Public Key: {npub}")
                            else:
                                self.pubkey_label.setText(f"Current Public Key: {self.pubkey_hex}")
                            self.extended_status.setText(f"Public key exported successfully")
                            
                            update_key_display()
                        else:
                            self.extended_status.setText("Failed to extract public key from TLV data")
                    else:
                        self.extended_status.setText(f"Card error: {sw1:02X}{sw2:02X}")
                else:
                    print(f"[ERROR] Response too short to contain SW1/SW2: {response.hex()}", file=sys.stderr)
                    self.extended_status.setText("Invalid response from card")
            except Exception as e:
                print(f"[ERROR] Export public key failed: {e}", file=sys.stderr)
                self.extended_status.setText(f"Export public key failed: {str(e)}")
        
        export_extended_btn.clicked.connect(dialog_export_extended_public_key)
        
        def populate_tree_from_existing_keys():
            self.key_tree.clear()
            
            recreated_items = {}
            
            root_keys = []
            for pubkey, data in self.derived_keys.items():
                if "parent" not in data or data["parent"] is None:
                    root_keys.append(pubkey)
            
            for pubkey in root_keys:
                data = self.derived_keys[pubkey]
                item = QTreeWidgetItem(self.key_tree)
                item.setText(0, data["path"])
                
                npub = data.get("npub") or hex_to_npub(pubkey)
                display_key = npub if npub else pubkey
                item.setText(1, display_key)
                item.setText(2, data.get("status", "Not Subscribed"))
                
                self.derived_keys[pubkey]["item"] = item
                recreated_items[pubkey] = item
            
            def process_children(parent_pubkey):
                for pubkey, data in self.derived_keys.items():
                    if data.get("parent") == parent_pubkey:
                        parent_item = recreated_items[parent_pubkey]
                        
                        child_item = QTreeWidgetItem(parent_item)
                        child_item.setText(0, data["path"])
                        
                        npub = data.get("npub") or hex_to_npub(pubkey)
                        display_key = npub if npub else pubkey
                        child_item.setText(1, display_key)
                        child_item.setText(2, data.get("status", "Not Subscribed"))
                        
                        self.derived_keys[pubkey]["item"] = child_item
                        recreated_items[pubkey] = child_item
                        
                        process_children(pubkey)
            
            for pubkey in root_keys:
                process_children(pubkey)
                
            for item in recreated_items.values():
                item.setExpanded(True)
                
            update_active_parent()
        
        if self.derived_keys:
            populate_tree_from_existing_keys()
        
        def on_dialog_closed(result):
            dialog.hide()
        
        dialog.rejected.connect(lambda: dialog.hide())
        
        update_key_display()
        
        dialog.setAttribute(Qt.WA_DeleteOnClose, False)
        dialog.resize(1000, 700)
        dialog.show()
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = NostrClientUI()
    window.resize(1000, 700)
    window.show()
    sys.exit(app.exec())
