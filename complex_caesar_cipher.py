## Cipher Code ##

import random
import string


class ComplexCaesarCipher:

    def __init__(self):
        self.copy_choice = False
        self.copied_text = ""

    def save_encrypted_to_file(self, encrypted_text, filename):
        with open(filename, "w") as file:
            file.write(encrypted_text)

    def generate_cycling_key(self, length, base_key):
        cycling_key = ""
        key_shift = 0
        for i in range(length):
            key_shift = (key_shift + 3) % 26  # Adjusted key shift to + 3
            key_char = chr((ord(base_key[i % len(base_key)]) - ord('a') + key_shift) % 26 + ord('a'))
            cycling_key += key_char
        return cycling_key

    def generate_random_passphrase(self):
        length = random.randint(2, 63)
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(length))

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

    def encrypt(self, text):
        text = self.preprocess_text(text)
        passphrase = self.generate_random_passphrase()
        cycling_key = self.generate_cycling_key(len(text), passphrase)
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

        # Combine the passphrase, encrypted text, and their lengths into one block
        encrypted_result = f"{passphrase}@{len(passphrase)}@{encrypted_text}"
        return encrypted_result


    
    def decrypt(self, encrypted_text):
        try:
            parts = encrypted_text.split('@')
            if len(parts) != 3:
                raise ValueError("Invalid format: passphrase, key, and code are not separated by '@'")
            passphrase = parts[0]
            key_len = int(parts[1])
            key = parts[2]
            encrypted_text = key
            cycling_key = self.generate_cycling_key(len(encrypted_text), passphrase)
            decrypted_text = ""
            i = 0
            while i < len(encrypted_text):
                char = encrypted_text[i]
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
                    i += 1
                    continue
                i += 1
            decrypted_text = self.reverse_preprocess_text(decrypted_text)
            return decrypted_text
        except ValueError as e:
            raise ValueError(f"Decryption error: {e}. Incorrect message format.")


def main():
    cipher = ComplexCaesarCipher()
    text = "Your message here"
    encrypted_text = cipher.encrypt(text)
    decrypted_text = cipher.decrypt(encrypted_text)
    print("Original Text:", text)
    print("Encrypted Text:", encrypted_text)
    print("Decrypted Text:", decrypted_text)


if __name__ == "__main__":
    main()
    
