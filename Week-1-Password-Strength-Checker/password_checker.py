import getpass

# List of commonly used passwords
COMMON_PASSWORDS = [
    "password",
    "password123",
    "12345678",
    "qwerty123",
    "admin123",
    "welcome123",
    "iloveyou",
    "abc12345"
]


# Function to check password strength
def check_password_strength(password):

    # 1. Check password length
    length = len(password)

    # 2. Check character types
    has_uppercase = any(char.isupper() for char in password)

    has_lowercase = any(char.islower() for char in password)

    has_digit = any(char.isdigit() for char in password)

    has_symbol = any(
        not char.isalnum() and not char.isspace()
        for char in password
    )

    # 3. Check for common passwords
    is_common = password.casefold() in COMMON_PASSWORDS

    # 4. Display password analysis
    print("\n========== PASSWORD ANALYSIS ==========")

    print("Password Length       :", length)
    print("Contains Uppercase    :", has_uppercase)
    print("Contains Lowercase    :", has_lowercase)
    print("Contains Number       :", has_digit)
    print("Contains Symbol       :", has_symbol)
    print("Common Password       :", is_common)

    # 5. Calculate password score
    score = sum([
        length >= 8,
        length >= 12,
        has_uppercase,
        has_lowercase,
        has_digit,
        has_symbol
    ])

    # 6. Determine password strength
    if is_common or length < 8 or score <= 2:
        strength = "WEAK"

    elif score >= 5 and length >= 12:
        strength = "STRONG"

    else:
        strength = "MEDIUM"

    print("\nPassword Strength:", strength)

    # 7. Generate improvement suggestions
    suggestions = []

    if length < 8:
        suggestions.append("Use at least 8 characters.")

    if length < 12:
        suggestions.append("Consider using 12 or more characters.")

    if not has_uppercase:
        suggestions.append("Add at least one uppercase letter.")

    if not has_lowercase:
        suggestions.append("Add at least one lowercase letter.")

    if not has_digit:
        suggestions.append("Add at least one number.")

    if not has_symbol:
        suggestions.append("Add at least one special symbol.")

    if is_common:
        suggestions.append("Avoid commonly used passwords.")

    # 8. Display suggestions
    print("\n========== SUGGESTIONS ==========")

    if suggestions:
        for suggestion in suggestions:
            print("-", suggestion)

    else:
        print("Your password meets all defined requirements!")

    print("\n========================================")


# 9. Main program
def main():

    print("========================================")
    print("       PASSWORD STRENGTH CHECKER")
    print("========================================")

    password = getpass.getpass("\nEnter your password: ")

    check_password_strength(password)


# Execute the program
if __name__ == "__main__":
    main()