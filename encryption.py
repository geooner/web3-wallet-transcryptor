import nacl.utils
import nacl.public
import base64
from typing import Dict, Union, Optional
from dataclasses import dataclass


@dataclass
class EncryptedMessage:
    version: str
    nonce: str
    ephemPublicKey: str
    ciphertext: str


class EncryptionError(Exception):
    """Base exception for encryption errors"""

    pass


class InvalidKeyError(EncryptionError):
    """Exception raised for invalid key errors"""

    pass


class InvalidMessageError(EncryptionError):
    """Exception raised for invalid message errors"""

    pass


class Encryption:
    VERSION = "x25519-xsalsa20-poly1305"
    MAX_MESSAGE_LENGTH = 1024 * 1024  # 1MB limit

    @staticmethod
    def _validate_message(msg: str) -> None:
        """
        Validate the message to be encrypted

        Args:
            msg: Message to validate

        Raises:
            InvalidMessageError: If message is invalid
        """
        if not isinstance(msg, str):
            raise InvalidMessageError("Message must be a string")

        if len(msg.encode("utf-8")) > Encryption.MAX_MESSAGE_LENGTH:
            raise InvalidMessageError(
                f"Message exceeds maximum length of {Encryption.MAX_MESSAGE_LENGTH} bytes"
            )

        if not msg:
            raise InvalidMessageError("Message cannot be empty")

    @staticmethod
    def _validate_public_key(key: str) -> None:
        """
        Validate the public key format

        Args:
            key: Public key to validate

        Raises:
            InvalidKeyError: If key is invalid
        """
        if not isinstance(key, str):
            raise InvalidKeyError("Public key must be a string")

        if not key:
            raise InvalidKeyError("Public key cannot be empty")

        try:
            decoded_key = base64.b64decode(key)
            if len(decoded_key) != nacl.public.PublicKey.SIZE:
                raise InvalidKeyError(f"Invalid public key length: {len(decoded_key)}")
        except Exception as e:
            raise InvalidKeyError(f"Invalid public key format: {str(e)}")

    @staticmethod
    def _encode_base64(data: bytes) -> str:
        """Safely encode bytes to base64 string"""
        try:
            return base64.b64encode(data).decode("utf-8")
        except Exception as e:
            raise EncryptionError(f"Failed to encode data: {str(e)}")

    @staticmethod
    def _decode_base64(data: str) -> bytes:
        """Safely decode base64 string to bytes"""
        try:
            return base64.b64decode(data)
        except Exception as e:
            raise EncryptionError(f"Failed to decode data: {str(e)}")

    def encrypt_message(self, receiver_public_key: str, msg: str) -> Dict[str, str]:
        """
        Encrypt a message using X25519-XSalsa20-Poly1305

        Args:
            receiver_public_key: Base64 encoded public key of the receiver
            msg: Message to encrypt

        Returns:
            Dict containing encrypted message data

        Raises:
            EncryptionError: If encryption fails
            InvalidKeyError: If public key is invalid
            InvalidMessageError: If message is invalid
        """
        try:
            # Validate inputs
            self._validate_message(msg)
            self._validate_public_key(receiver_public_key)

            # Generate ephemeral keypair
            ephemeral_keypair = nacl.public.PrivateKey.generate()

            # Decode receiver's public key
            pub_key_bytes = base64.b64decode(receiver_public_key)
            receiver_key = nacl.public.PublicKey(pub_key_bytes)

            # Convert message to bytes
            msg_bytes = msg.encode("utf-8")

            # Generate random nonce
            nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)

            # Create encryption box
            box = nacl.public.Box(ephemeral_keypair, receiver_key)

            # Encrypt the message
            encrypted_message = box.encrypt(msg_bytes, nonce)[
                24:
            ]  # Remove nonce from returned bytes

            # Create encrypted message object
            encrypted_data = EncryptedMessage(
                version=self.VERSION,
                nonce=self._encode_base64(nonce),
                ephemPublicKey=self._encode_base64(
                    ephemeral_keypair.public_key.encode()
                ),
                ciphertext=self._encode_base64(encrypted_message),
            )

            return vars(encrypted_data)

        except (InvalidKeyError, InvalidMessageError):
            raise
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {str(e)}")

    def decrypt_message(self, private_key: str, encrypted_data: Dict[str, str]) -> str:
        """
        Decrypt a message using X25519-XSalsa20-Poly1305

        Args:
            private_key: Base64 encoded private key of the receiver
            encrypted_data: Dictionary containing the encrypted message data

        Returns:
            Decrypted message as string

        Raises:
            EncryptionError: If decryption fails
            InvalidKeyError: If private key is invalid
            InvalidMessageError: If encrypted data is invalid
        """
        try:
            # Validate encrypted data structure
            required_fields = {"version", "nonce", "ephemPublicKey", "ciphertext"}
            if not all(field in encrypted_data for field in required_fields):
                raise InvalidMessageError("Missing required fields in encrypted data")

            if encrypted_data["version"] != self.VERSION:
                raise InvalidMessageError(
                    f"Unsupported version: {encrypted_data['version']}"
                )

            # Decode private key
            try:
                priv_key_bytes = self._decode_base64(private_key)
                receiver_private_key = nacl.public.PrivateKey(priv_key_bytes)
            except Exception as e:
                raise InvalidKeyError(f"Invalid private key: {str(e)}")

            # Decode message components
            try:
                nonce = self._decode_base64(encrypted_data["nonce"])
                ephem_public_key = nacl.public.PublicKey(
                    self._decode_base64(encrypted_data["ephemPublicKey"])
                )
                ciphertext = self._decode_base64(encrypted_data["ciphertext"])
            except Exception as e:
                raise InvalidMessageError(f"Invalid message format: {str(e)}")

            # Create decryption box
            box = nacl.public.Box(receiver_private_key, ephem_public_key)

            # Decrypt the message
            decrypted_message = box.decrypt(ciphertext, nonce)

            # Convert bytes to string
            try:
                return decrypted_message.decode("utf-8")
            except UnicodeDecodeError as e:
                raise EncryptionError(f"Failed to decode decrypted message: {str(e)}")

        except (InvalidKeyError, InvalidMessageError):
            raise
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {str(e)}")

    @classmethod
    def create(cls) -> "Encryption":
        """Factory method for creating Encryption instances"""
        return cls()

    @staticmethod
    def generate_key_pair() -> Dict[str, str]:
        """
        Generate a new X25519 key pair for encryption/decryption

        Returns:
            Dictionary containing base64-encoded 'privateKey' and 'publicKey'

        Raises:
            EncryptionError: If key generation fails
        """
        try:
            # Generate new private key
            private_key = nacl.public.PrivateKey.generate()

            # Get corresponding public key
            public_key = private_key.public_key

            return {
                "privateKey": base64.b64encode(bytes(private_key)).decode("utf-8"),
                "publicKey": base64.b64encode(bytes(public_key)).decode("utf-8"),
            }
        except Exception as e:
            raise EncryptionError(f"Key generation failed: {str(e)}")

    @staticmethod
    def get_public_key(private_key: str) -> str:
        """
        Derive the public key from a private key

        Args:
            private_key: Base64 encoded private key

        Returns:
            Base64 encoded public key

        Raises:
            InvalidKeyError: If private key is invalid
            EncryptionError: If public key derivation fails
        """
        try:
            # Decode and validate private key
            priv_key_bytes = base64.b64decode(private_key)
            private_key_obj = nacl.public.PrivateKey(priv_key_bytes)

            # Get corresponding public key
            public_key = private_key_obj.public_key

            return base64.b64encode(bytes(public_key)).decode("utf-8")
        except Exception as e:
            raise InvalidKeyError(f"Invalid private key: {str(e)}")

    @staticmethod
    def validate_encrypted_message_format(encrypted_data: Dict[str, str]) -> None:
        """
        Validate the format of an encrypted message dictionary

        Args:
            encrypted_data: Dictionary containing encrypted message data

        Raises:
            InvalidMessageError: If the format is invalid
        """
        required_fields = {"version", "nonce", "ephemPublicKey", "ciphertext"}

        if not isinstance(encrypted_data, dict):
            raise InvalidMessageError("Encrypted data must be a dictionary")

        if missing := required_fields - set(encrypted_data.keys()):
            raise InvalidMessageError(f"Missing required fields: {', '.join(missing)}")

        for field in required_fields:
            if not isinstance(encrypted_data[field], str):
                raise InvalidMessageError(f"Field '{field}' must be a string")
            if not encrypted_data[field]:
                raise InvalidMessageError(f"Field '{field}' cannot be empty")

    @staticmethod
    def is_valid_key(key: str, key_type: str = "public") -> bool:
        """
        Check if a key string is valid without raising exceptions

        Args:
            key: Base64 encoded key to validate
            key_type: Type of key to validate ("public" or "private")

        Returns:
            bool: True if key is valid, False otherwise
        """
        try:
            decoded_key = base64.b64decode(key)
            if key_type == "public":
                return len(decoded_key) == nacl.public.PublicKey.SIZE
            else:  # private key
                nacl.public.PrivateKey(decoded_key)
                return True
        except Exception:
            return False

    @staticmethod
    def format_key(key: Union[str, bytes], input_encoding: str = "raw") -> str:
        """
        Convert a key from various formats to base64 encoded string

        Args:
            key: Key to format (can be bytes or base64/hex string)
            input_encoding: Format of input key ("raw", "base64", or "hex")

        Returns:
            Base64 encoded key string

        Raises:
            InvalidKeyError: If key format is invalid
        """
        try:
            if input_encoding == "raw" and isinstance(key, bytes):
                return base64.b64encode(key).decode("utf-8")
            elif input_encoding == "base64" and isinstance(key, str):
                # Validate it's actually base64
                base64.b64decode(key)
                return key
            elif input_encoding == "hex" and isinstance(key, str):
                return base64.b64encode(bytes.fromhex(key)).decode("utf-8")
            else:
                raise InvalidKeyError("Invalid key format or encoding specified")
        except Exception as e:
            raise InvalidKeyError(f"Failed to format key: {str(e)}")
