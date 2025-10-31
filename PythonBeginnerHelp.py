# Welcome to a beginner's guide to Python!
# This script will walk you through the fundamental concepts.
# You can run this file and see the output for each section.

print("="*20, "Welcome to Python Basics!", "="*20)

# 1. VARIABLES and DATA TYPES
# Variables are containers for storing data values.
print("\n--- [1] Variables and Data Types ---")

name = "Alice"      # String (text)
age = 30            # Integer (whole number)
height = 5.5        # Float (number with a decimal)
is_student = True   # Boolean (True or False)

# The print() function displays output to the console.
# f-strings (like f"...") are a modern way to format strings.
print(f"Name: {name} (Type: {type(name)})")
print(f"Age: {age} (Type: {type(age)})")
print(f"Height: {height} (Type: {type(height)})")
print(f"Is Student: {is_student} (Type: {type(is_student)})")


# 2. LISTS
# A list is a collection of items in a particular order.
print("\n--- [2] Lists ---")

fruits = ["apple", "banana", "cherry"]
print(f"Original list of fruits: {fruits}")

# You can access items by their index (starting from 0).
print(f"The first fruit is: {fruits[0]}")

# You can add an item to the end of the list.
fruits.append("orange")
print(f"List after adding 'orange': {fruits}")


# 3. DICTIONARIES
# A dictionary stores data in key-value pairs.
print("\n--- [3] Dictionaries ---")

person = {
    "name": "Bob",
    "age": 25,
    "city": "New York"
}
print(f"Original dictionary: {person}")

# You access values by their key.
print(f"Bob's city is: {person['city']}")

# You can add a new key-value pair.
person["job"] = "Engineer"
print(f"Dictionary after adding a job: {person}")


# 4. CONDITIONAL STATEMENTS (if/elif/else)
# These allow you to run different code based on conditions.
print("\n--- [4] Conditional Statements ---")

temperature = 25

if temperature > 30:
    print("It's a hot day!")
elif temperature > 20:
    print("It's a pleasant day.")
else:
    print("It's a cold day.")


# 5. LOOPS
# Loops are used to repeat a block of code.
print("\n--- [5] Loops ---")

# 'for' loop: iterates over a sequence (like a list).
print("Printing fruits using a 'for' loop:")
for fruit in fruits:
    print(f"- {fruit}")

# 'while' loop: repeats as long as a condition is true.
print("\nCounting down with a 'while' loop:")
count = 3
while count > 0:
    print(count)
    count = count - 1 # or count -= 1
print("Blast off!")


# 6. FUNCTIONS
# Functions are reusable blocks of code that perform a specific task.
print("\n--- [6] Functions ---")

# This function takes a name and returns a greeting.
def greet(person_name):
    """This is a docstring. It explains what the function does."""
    return f"Hello, {person_name}! Welcome."

# Call the function and print its return value.
greeting_message = greet("Charlie")
print(greeting_message)
print(greet("Dana")) # You can also call it directly in a print statement.


# 7. USER INPUT
# The input() function gets input from the user.
print("\n--- [7] User Input ---")

user_name = input("What is your name? ")
print(f"Nice to meet you, {user_name}!")

# Note: input() always returns a string. If you need a number, you must convert it.
try:
    user_age_str = input("How old are you? ")
    user_age_int = int(user_age_str) # Convert string to integer
    print(f"You will be {user_age_int + 1} on your next birthday.")
except ValueError:
    print("That wasn't a valid number!")
