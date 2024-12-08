import streamlit as st
import streamlit_authenticator as stauth
import json
import firebase_admin
from firebase_admin import credentials, db
from datetime import datetime
from dotenv import load_dotenv
from passlib.hash import bcrypt
import logging

# Load Firebase configuration from Streamlit secrets
firebase_config_secret = st.secrets.get("FIREBASE_CONFIG_PATH", None)

if firebase_config_secret:
    try:
        # Parse the Firebase configuration JSON
        firebase_config_dict = json.loads(firebase_config_secret, strict=False)

        # Validate config structure (optional)
        if not all(key in firebase_config_dict for key in ["type"]):
            raise ValueError("Missing required key(s) in Firebase config")

        # Initialize Firebase only if it is not already initialized
        if not firebase_admin._apps:
            if firebase_config_dict["type"] == "certificate":
                cred = credentials.Certificate(firebase_config_dict)
            else:
                # Handle other credential types (e.g., service account)
                raise NotImplementedError("Unsupported Firebase credential type")

            firebase_admin.initialize_app(cred, {
                "databaseURL": "https://cgpa-percentage-default-rtdb.firebaseio.com/"
            })
    except (json.JSONDecodeError, ValueError) as e:
        logging.error(f"Invalid Firebase configuration: {e}")
        st.error("Error loading Firebase configuration. Please check your secrets.")
    except Exception as e:
        logging.exception(f"Error initializing Firebase: {e}")
        st.error(f"Error initializing Firebase: {e}")
else:
    st.error("Firebase configuration not found in Streamlit secrets.")

# Firebase Helper Functions
def fetch_user_data():
    try:
        ref = db.reference("users")
        data = ref.get() or {}

        users = {}
        for user_id, user_data in data.items():
            username = user_data.get("username", "")
            password = user_data.get("password", "")
            name = user_data.get("name", "")
            email = user_data.get("email", "")

            # Add validation or error handling for empty usernames and passwords
            if not username or not password:
                logging.warning(f"User {user_id} has empty username or password.")
                continue

            users[user_id] = {
                "username": username,
                "password": password,
                "name": name,
                "email": email
            }

        return users
    except firebase_admin.exceptions.FirebaseError as e:
        logging.error(f"Failed to fetch user data: {e}")
        st.error(f"Error fetching user data: {e}")
        return {}
    except Exception as e:
        logging.exception(f"Unexpected error: {e}")
        st.error("An unexpected error occurred.")
        return {}

def add_user_to_firebase(username, name, email, password):
    try:
        # Basic input validation
        if not all([username, name, email, password]):
            st.error("All fields are required.")
            return False

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        # Reference to the "users" node in Firebase
        ref = db.reference("users")

        # Add user data to Firebase
        ref.child(username).set({
            "username": username,
            "name": name,
            "email": email,
            "password": hashed_password
        })

        st.success("User added successfully!")
        return True
    except firebase_admin.exceptions.FirebaseError as e:
        logging.error(f"Failed to add user: {e}")
        st.error(f"Error adding user: {e}")
        return False
    except Exception as e:
        logging.exception(f"Unexpected error: {e}")
        st.error("An unexpected error occurred. Please try again later.")
        return False

# Function to calculate percentage from CGPA
def calculate_percentage_and_grade(cgpa):
    if cgpa < 0 or cgpa > 10:
        return "Invalid CGPA", "Invalid CGPA"

    grade_mapping = {
        (9.5, 10): (lambda x: 20*x-100, "Outstanding (O)"),
        (8.25, 9.5): (lambda x: 12*x-25, "Excellent (A+)"),
        (6.75, 8.25): (lambda x: 10*x-7.5, "Very Good (A)"),
        (5.75, 6.75): (lambda x: 5*x+26.25, "Good (B+)"),
        (4.75, 5.75): (lambda x: 10*x-2.5, "Above Average (B)"),
        (4.0, 4.75): (lambda x: 6.6*x+13.6, "Pass (D)"),
    }

    for (lower_bound, upper_bound), (percentage_func, grade) in grade_mapping.items():
        if lower_bound <= cgpa <= upper_bound:
            return percentage_func(cgpa), grade

    return "Invalid CGPA", "Invalid CGPA"

# Load user data from Firebase
users = fetch_user_data()

if not users:
    st.warning("No users found in Firebase. Please add users first.")
    st.stop()  # Stop further execution if no users are found

usernames = list(users.keys())  # Extract usernames from the `users` dictionary
names = [users[username]["name"] for username in usernames]
hashed_passwords = [users[username]["password"] for username in usernames]

# Create credentials for streamlit-authenticator
credentials = {
    "usernames": {
        username: {
            "name": users[username]["name"],
            "email": users[username]["email"],
            # Avoid storing plain-text passwords
            "password": bcrypt.hashpw(users[username]["password"].encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        }
        for username in usernames
    }
}

authenticator = stauth.Authenticate(
    credentials=credentials,
    cookie_name="auth_cookie",
    key="secret_key",
    cookie_expiry_days=30,
)

# User action
action = st.selectbox("Choose an option", ("Login", "Sign Up"))

if action == "Sign Up":
    st.title("Sign Up")
    new_username = st.text_input("Username", "").strip()
    new_name = st.text_input("Full Name", "").strip()
    new_email = st.text_input("Email", "").strip()
    new_password = st.text_input("Password", "", type="password").strip()
    confirm_password = st.text_input("Confirm Password", "", type="password").strip()

    if st.button("Create Account"):
        if not new_username or not new_name or not new_email or not new_password:
            st.error("All fields are required. Please fill in all details.")
        elif new_password != confirm_password:
            st.error("Passwords do not match. Please try again.")
        elif new_username in users:
            st.error("Username already exists. Please choose a different username.")
        else:
            result = add_user_to_firebase(new_username, new_name, new_email, new_password)
            if result:
                st.success("Account created successfully! Please log in.")
            else:
                st.error("Account creation failed. Please try again.")


elif action == "Login":
    st.title("Login")
    # Attempt to login
    result = authenticator.login(location="main")

    if result is not None:
        name, authentication_status, username = result

        if authentication_status:
            stored_hash = users.get(username, {}).get("password", "")
            input_password = st.text_input("Password", "", type="password").strip()

            # Check if the password matches
            if verify_password(stored_hash, input_password):
                st.success(f"Welcome {name}!")
                authenticator.logout("Logout", "sidebar")

                # Content to show after successful login
                st.subheader("Welcome to the CGPA Calculator!")

                # Number of years of CGPA data
                n = st.number_input("Enter the number of years of CGPA data (1 to 4):", min_value=1, max_value=4, step=1)

                cgpas = []
                percentages = []
                total_cgpa = 0
                total_percentage = 0

                # Input CGPAs and calculate percentages
                for i in range(n):
                    cgpa = st.number_input(f"Enter CGPA for year {i+1} (4.00 - 10.00):", min_value=4.00, max_value=10.00, step=0.01)
                    if cgpa:
                        cgpas.append(cgpa)
                        total_cgpa += cgpa

                        percentage, grade = calculate_percentage_and_grade(cgpa)
                        if percentage == "Invalid CGPA":
                            st.error(f"Invalid CGPA entered for year {i+1}. Please enter a valid CGPA.")
                            break
                        percentages.append(percentage)
                        total_percentage += percentage

                # Display results if valid
                if len(cgpas) == n:
                    aggregate_percentage = total_percentage / n
                    aggregate_cgpa = total_cgpa / n
                    grade = calculate_grade(aggregate_cgpa)

                    st.subheader("CGPA to Percentage Conversion Results")
                    for i, (cgpa, percentage) in enumerate(zip(cgpas, percentages), start=1):
                        st.write(f"Year {i}: CGPA = {cgpa:.2f}, Percentage = {percentage:.2f}%")
                    st.write(f"Aggregate CGPA: {aggregate_cgpa:.2f}")
                    st.write(f"Aggregate Percentage: {aggregate_percentage:.2f}%")
                    st.write(f"Grade: {grade}")
                else:
                    st.error("Incorrect password. Please try again.")
        else:
            st.error("Invalid credentials. Please try again.")
    else:
        st.error("Authentication process failed. Please try again.")
