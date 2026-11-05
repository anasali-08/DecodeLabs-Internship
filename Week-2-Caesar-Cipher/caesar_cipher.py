# ==========================================
#       CAESAR CIPHER ENCRYPTION
#       Cybersecurity Internship - Week 2
# ==========================================


# Function to encrypt the message
def encrypt(text, shift):

    encrypted_text = ""

    for char in text:

        # Check uppercase letters
        if char.isupper():

            encrypted_char = chr(
                (ord(char) - ord('A') + shift) % 26 + ord('A')
            )

            encrypted_text += encrypted_char

        # Check lowercase letters
        elif char.islower():

            encrypted_char = chr(
                (ord(char) - ord('a') + shift) % 26 + ord('a')
            )

            encrypted_text += encrypted_char

        # Preserve spaces, numbers and symbols
        else:
            encrypted_text += char

    return encrypted_text


# Function to decrypt the message
def decrypt(text, shift):

    decrypted_text = ""

    for char in text:

        # Reverse uppercase letters
        if char.isupper():

            decrypted_char = chr(
                (ord(char) - ord('A') - shift) % 26 + ord('A')
            )

            decrypted_text += decrypted_char

        # Reverse lowercase letters
        elif char.islower():

            decrypted_char = chr(
                (ord(char) - ord('a') - shift) % 26 + ord('a')
            )

            decrypted_text += decrypted_char

        # Preserve spaces, numbers and symbols
        else:
            decrypted_text += char

    return decrypted_text


# Main program
def main():

    print("=" * 45)
    print("       CAESAR CIPHER ENCRYPTION")
    print("       CYBERSECURITY INTERNSHIP")
    print("=" * 45)

    # Get input from user
    message = input("\nEnter your message: ")

    # Get shift key
    try:
        shift = int(input("Enter shift key: "))

    except ValueError:
        print("\nError: Please enter a valid integer.")
        return

    # Normalize shift key
    shift = shift % 26

    # Encryption
    encrypted_message = encrypt(message, shift)

    print("\n----------- ENCRYPTION -----------")

    print("Original Message  :", message)
    print("Shift Key         :", shift)
    print("Encrypted Message :", encrypted_message)

    # Decryption
    decrypted_message = decrypt(encrypted_message, shift)

    print("\n----------- DECRYPTION -----------")

    print("Encrypted Message :", encrypted_message)
    print("Decrypted Message :", decrypted_message)

    print("\n========================================")
    print("       OPERATION COMPLETED")
    print("========================================")


# Execute the program
if __name__ == "__main__":
    main()