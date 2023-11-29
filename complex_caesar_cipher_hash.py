import string

class ComplexCaesarCipherHash:

    def __init__(self):
        pass

    def preprocess_text(self, text):
        # Replace characters with special codes
        text = text.replace('\n', '1R2').replace(' ', '1S2').replace('.', '1A2').replace('-', '1B2').replace('_', '1C2').replace(',', '1D2').replace("'", "1E2")
        text = text.replace(':', '1F2').replace('@', '1G2').replace('"', '1H2').replace(';', '1I2').replace('!', '1J2').replace('£', '1K2').replace('$', '1L2').replace('%', '1M2')
        text = text.replace('^', '1N2').replace('&', '1O2').replace('(', '1P2').replace(')', '1Q2').replace('*', '1T2').replace('+', '1U2').replace('=', '1V2').replace('?', '1W2').replace('=', '1X2').replace('#', '1Z2')
        text = text.replace('{', '3A4').replace('}', '3B4').replace('[', '3C4').replace(']', '3D4').replace('<', '3E4').replace('>', '3F4').replace('/', '3G4').replace('\\', '3H4').replace('|', '3I4').replace('~', '3J4')
        return text

    def reverse_preprocess_text(self, text):
        # Reverse the preprocessing: replace special codes with characters
        text = text.replace('1R2', '\n').replace('1S2', ' ').replace('1A2', '.').replace('1B2', '-').replace('1C2', '_').replace('1D2', ',').replace("1E2", "'")
        text = text.replace('1F2', ':').replace('1G2', '@').replace('1H2', '"').replace('1I2', ';').replace('1J2', '!' ).replace('1K2', '£').replace('1L2', '$').replace('1M2', '%')
        text = text.replace('1N2', '^').replace('1O2', '&').replace('1P2', '(').replace('1Q2', ')').replace('1T2', '*').replace('1U2', '+').replace('1V2', '=').replace('1W2', '?').replace('1X2', '=').replace('1Z2', '#')
        text = text.replace('3A4', '{').replace('3B4', '}').replace('3C4', '[').replace('3D4', ']').replace('3E4', '<').replace('3F4', '>').replace('3G4', '/').replace('3H4', '\\').replace('3I4', '|').replace('3J4', '~')
        return text

    def generate_cycling_key(self, length, hash_key):
        cycling_key = ""
        key_shift = 0
        for i in range(length):
            key_shift = (key_shift + 2) % 26  # Adjusted key shift to + 2
            key_char = chr((ord(hash_key[i % len(hash_key)]) - ord('a') + key_shift) % 26 + ord('a'))
            cycling_key += key_char
        return cycling_key

    def encrypt_with_hash(self, text, hash_key):
        processed_text = self.preprocess_text(text)
        cycling_key = self.generate_cycling_key(len(processed_text), hash_key)
        encrypted_text = self.encrypt_text_with_cycling_key(processed_text, cycling_key)
        encrypted_result = f"{hash_key}@{len(hash_key)}@{encrypted_text}"
        return encrypted_result

    def decrypt_with_hash(self, encrypted_text, hash_key):
        parts = encrypted_text.split('@')
        if len(parts) != 3:
            raise ValueError("Invalid format: hash key, key length, and message are not separated by '@'")
        message_hash = parts[0]
        key_len = int(parts[1])
        encrypted_message = parts[2]
        cycling_key = self.generate_cycling_key(len(encrypted_message), message_hash)
        decrypted_text = self.decrypt_text_with_cycling_key(encrypted_message, cycling_key)
        return self.reverse_preprocess_text(decrypted_text)

    def encrypt_text_with_cycling_key(self, text, cycling_key):
        encrypted_text = ""
        for i, char in enumerate(text):
            if char.isalpha() or char.isdigit():
                shift = ord(cycling_key[i]) - ord('a')
                if char.isupper():
                    encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
                elif char.islower():
                    encrypted_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
                else:
                    encrypted_char = chr((ord(char) - ord('0') + shift) % 10 + ord('0'))
                encrypted_text += encrypted_char
            else:
                encrypted_text += char
        return encrypted_text

    def decrypt_text_with_cycling_key(self, text, cycling_key):
        decrypted_text = ""
        for i, char in enumerate(text):
            if char.isalpha() or char.isdigit():
                shift = ord(cycling_key[i]) - ord('a')
                if char.isupper():
                    decrypted_char = chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A'))
                elif char.islower():
                    decrypted_char = chr((ord(char) - ord('a') - shift + 26) % 26 + ord('a'))
                else:
                    decrypted_char = chr((ord(char) - ord('0') - shift + 10) % 10 + ord('0'))
                decrypted_text += decrypted_char
            else:
                decrypted_text += char
        return decrypted_text


def main():
    cipher = ComplexCaesarCipherHash()
    text = "Your message here"
    hash_key = "your_hash_key"  # replace with your desired hash key
    encrypted_text = cipher.encrypt_with_hash(text, hash_key)
    decrypted_text = cipher.decrypt_with_hash(encrypted_text, hash_key)
    print("Original Text:", text)
    print("Encrypted Text:", encrypted_text)
    print("Decrypted Text:", decrypted_text)


if __name__ == "__main__":
    main()
