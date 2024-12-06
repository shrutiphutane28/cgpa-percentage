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

if not firebase_admin._apps:
    firebase_config_dict = json.loads(firebase_config_json, strict=False)

    # Define the credential using the dictionary loaded from JSON
    cred = credentials.Certificate(firebase_config_dict)
    
    # Initialize Firebase
    firebase_admin.initialize_app(cred, {
        "databaseURL": "https://cgpa-percentage-default-rtdb.firebaseio.com/"
    })

# Function to calculate percentage from CGPA
def calculate_percentage(cgpa):
    if cgpa < 0 or cgpa > 10:
        return "Invalid CGPA"  # Handle invalid CGPA values
    if cgpa >= 9.50:
        return 20 * cgpa - 100  # Outstanding (O)
    elif cgpa >= 8.25:
        return 12 * cgpa - 25  # Excellent (A+)
    elif cgpa >= 6.75:
        return 10 * cgpa - 7.5  # Very Good (A)
    elif cgpa >= 5.75:
        return 5 * cgpa + 26.25  # Good (B+)
    elif cgpa >= 4.75:
        return 10 * cgpa - 2.5  # Above Average (B) or Average I (C)
    elif cgpa >= 4.00:
        return 6.6 * cgpa + 13.6  # Pass (D)
    else:
        return "Invalid CGPA"

# Function to calculate grade based on CGPA
def calculate_grade(cgpa):
    if cgpa < 0 or cgpa > 10:
        return "Invalid CGPA"  # Handle invalid CGPA values
    if cgpa >= 9.50:
        return "Outstanding (O)"
    elif cgpa >= 8.25:
        return "Excellent (A+)"
    elif cgpa >= 6.75:
        return "Very Good (A)"
    elif cgpa >= 5.75:
        return "Good (B+)"
    elif cgpa >= 4.75:
        return "Above Average (B)"
    elif cgpa >= 4.00:
        return "Pass (D)"
    else:
        return "Invalid CGPA"

# Firebase Helper Functions
def fetch_user_data():
    try:
        ref = db.reference("users")
        data = ref.get() or {}
        return {
            user.get("username", ""): {
                "name": user.get("name", ""),
                "password": user.get("password", ""),
                "email": user.get("email", ""),
            }
            for user in data.values()
        }
    except Exception as e:
        st.error(f"Failed to fetch user data: {e}")
        return {}
    
import bcrypt

def add_user_to_firebase(username, name, email, password):
    try:
        # Validate inputs
        if not username or not name or not email or not password:
            st.error("All fields are required.")
            return False

        if "@" not in email or "." not in email.split("@")[-1]:
            st.error("Invalid email format.")
            return False

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Reference to "users" node in Firebase
        ref = db.reference("users")

        # Add user data to Firebase
        ref.child(username).set({
            "username": username,
            "name": name,
            "email": email,
            "password": hashed_password
        })

        return True
    except Exception as e:
        # Log and display a generic error
        st.error("Failed to add user. Please try again later.")
        print(f"Error adding user: {e}")  # Optional logging for debugging
        return False

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
        usernames[i]: {
            "name": names[i],
            "email": users[usernames[i]]["email"],
            "password": hashed_passwords[i],
        }
        for i in range(len(usernames))
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
    result = authenticator.login(location="main")
    
    if result is not None:
        name, authentication_status, username = result
        
        if authentication_status:
            authenticator.logout("Logout", "main")
            st.success(f"Welcome {name}!")

            # Number of years of CGPA data
        n = st.number_input("Enter the number of years of CGPA data (1 to 4):", min_value=1, max_value=4, step=1)

        if n:
            cgpas = []
            percentages = []
            total_cgpa, total_percentage = 0, 0

            # Input CGPAs and calculate percentages
            for i in range(n):
                cgpa = st.number_input(
                    f"Enter CGPA for year {i+1} (4.00 - 10.00):",
                    min_value=4.00, max_value=10.00, step=0.01,
                )
                cgpas.append(cgpa)
                total_cgpa += cgpa

                percentage = calculate_percentage(cgpa)
                if percentage == -1:
                    st.error(f"Invalid CGPA entered for year {i+1}. Please enter a valid CGPA.")
                    break
                percentages.append(percentage)
                total_percentage += percentage

            # Display results if all years are valid
            if len(cgpas) == n:
                aggregate_percentage = total_percentage / n
                aggregate_cgpa = total_cgpa / n
                grade = calculate_grade(aggregate_cgpa)

                st.subheader("CGPA to Percentage Conversion Results")
                for i, (cgpa, percentage) in enumerate(zip(cgpas, percentages), start=1):
                    st.write(f"Year {i}: CGPA = {cgpa}, Percentage = {percentage:.2f}%")
                st.write(f"Aggregate CGPA: {aggregate_cgpa:.2f}")
                st.write(f"Aggregate Percentage: {aggregate_percentage:.2f}%")
                st.write(f"Grade: {grade}")
                
        else:
            st.error("Invalid credentials")
    else:
        st.error("Authentication process failed. Please try again.")
