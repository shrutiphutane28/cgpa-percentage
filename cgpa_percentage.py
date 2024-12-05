import streamlit as st
import streamlit_authenticator as stauth
import json
import firebase_admin
from firebase_admin import credentials, db
from datetime import datetime
from dotenv import load_dotenv
from passlib.hash import bcrypt

# Load Firebase configuration from Streamlit secrets
firebase_config_json = st.secrets["general"].get("FIREBASE_CONFIG_PATH", None)

if firebase_config_json:
    # Parse the JSON string
    firebase_config_dict = json.loads(firebase_config_json, strict=False)

    # Initialize Firebase Admin SDK if not already initialized
    if not firebase_admin._apps:
        cred = credentials.Certificate(firebase_config_dict)
        firebase_admin.initialize_app(cred, {
            "databaseURL": "https://cgpa-percentage-default-rtdb.firebaseio.com/"
        })
else:
    st.error("Firebase configuration not found. Please set the FIREBASE_CONFIG in secrets.toml.")


# Function to calculate percentage from CGPA
def calculate_percentage(cgpa):
    if cgpa >= 9.50:
        return 20 * cgpa - 100  # Outstanding (O)
    elif cgpa >= 8.25 and cgpa < 9.50:
        return 12 * cgpa - 25  # Excellent (A+)
    elif cgpa >= 6.75 and cgpa < 8.25:
        return 10 * cgpa - 7.5  # Very Good (A)
    elif cgpa >= 5.75 and cgpa < 6.75:
        return 5 * cgpa + 26.25  # Good (B+)
    elif cgpa >= 5.25 and cgpa < 5.75:
        return 10 * cgpa - 2.5  # Above Average (B)
    elif cgpa >= 4.75 and cgpa < 5.25:
        return 10 * cgpa - 2.5  # Average I (C)
    elif cgpa >= 4.00 and cgpa < 4.75:
        return 6.6 * cgpa + 13.6  # Pass (D)
    else:
        return -1  # Invalid CGPA

def calculate_grade(aggregate_cgpa):
    if aggregate_cgpa >= 9.50:
        return "Outstanding (O)"
    elif aggregate_cgpa >= 8.25:
        return "Excellent (A+)"
    elif aggregate_cgpa >= 6.75:
        return "Very Good (A)"
    elif aggregate_cgpa >= 5.75:
        return "Good (B+)"
    elif aggregate_cgpa >= 5.25:
        return "Above Average (B)"
    elif aggregate_cgpa >= 4.75:
        return "Average I (C)"
    elif aggregate_cgpa >= 4.00:
        return "Pass (D)"
    else:
        return "Invalid CGPA"

# Firebase Helper Functions
def fetch_user_data():
    try:
        ref = db.reference("users")
        data = ref.get() or {}
        return {user.get("username", ""): {"name": user.get("name", ""), "password": user.get("password", "")} for user in data.values()}
    except Exception as e:
        st.error(f"Failed to fetch user data: {e}")
        return {}

def add_user_to_firebase(username, name, password):
    try:
        hashed_password = bcrypt.hash(password)
        ref = db.reference("users")
        ref.push({
            "username": username,
            "name": name,
            "password": hashed_password
        })
        return True
    except Exception as e:
        st.error(f"Failed to add user: {e}")
        return False

# Load user data from Firebase
users = fetch_user_data()
if not users:
    st.warning("No users found in Firebase. Please add users first.")

names = [users[user]["name"] for user in users]
usernames = list(users.keys())
hashed_passwords = [users[user]["password"] for user in users]

# Setup authenticator
authenticator = stauth.Authenticate(
    credentials={"usernames": {usernames[i]: {"name": names[i], "password": hashed_passwords[i]} for i in range(len(usernames))}},
    cookie_name="auth_cookie",
    key="secret_key",
    cookie_expiry_days=30
)

# User sign-up or log-in section
action = st.selectbox("Choose an option", ("Login", "Sign Up"))

if action == "Sign Up":
    st.title("Sign Up")
    new_username = st.text_input("Username", "")
    new_name = st.text_input("Full Name", "")
    new_password = st.text_input("Password", "", type="password")
    confirm_password = st.text_input("Confirm Password", "", type="password")

    if st.button("Create Account"):
        if new_password == confirm_password:
            # Check if the username already exists
            if new_username not in usernames:
                # Add the new user to Firebase
                add_user_to_firebase(new_username, new_name, new_password)

                # Show success message
                st.success("Account created successfully! Please log in.")
            else:
                st.error("Username already exists. Please choose a different username.")
        else:
            st.error("Passwords do not match. Please try again.")

elif action == "Login":
    st.title("Login")
    name, authentication_status, username = authenticator.login("Login", "sidebar")

    if authentication_status:
        st.success(f"Welcome {name}!")

        # Get the number of years of CGPA data
        n = st.number_input("Enter the number of years of CGPA data (1 to 4):", min_value=1, max_value=4, step=1)

        if n:
            cgpas = []
            percentages = []
            total_percentage = 0
            total_cgpa = 0

            # Input CGPAs and calculate percentages
            for i in range(n):
                cgpa = st.number_input(f"Enter CGPA for year {i+1} (4.00 - 10.00):", min_value=4.00, max_value=10.00, step=0.01)
                cgpas.append(cgpa)
                total_cgpa += cgpa

                # Calculate percentage
                percentage = calculate_percentage(cgpa)
                if percentage == -1:
                    st.error(f"Invalid CGPA entered for year {i+1}. Please enter a valid CGPA.")
                    break
                percentages.append(percentage)
                total_percentage += percentage

            # Calculate aggregate percentage
            if len(cgpas) == n:
                aggregate_percentage = total_percentage / n
                aggregate_cgpa = total_cgpa / n
                grade = calculate_grade(aggregate_cgpa)

                # Display results
                st.subheader("CGPA to Percentage Conversion Results")
                for i in range(n):
                    st.write(f"Year {i+1}: CGPA = {cgpas[i]}, Percentage = {percentages[i]}%")
                st.write(f"Aggregate CGPA: {aggregate_cgpa:.2f}")
                st.write(f"Aggregate Percentage: {aggregate_percentage:.2f}%")
                st.write(f"Grade: {grade}")
    elif authentication_status is False:
        st.error("Invalid credentials.")
    else:
        st.info("Please log in.")

if authentication_status:
    if authenticator.logout("Logout", "sidebar"):
        st.info("Logged out.")
