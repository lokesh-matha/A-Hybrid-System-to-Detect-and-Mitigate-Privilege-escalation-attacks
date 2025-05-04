import streamlit as st
import pandas as pd
import pickle
import os
import base64
import streamlit as st
from streamlit.components.v1 import html
def set_background_and_styles():
    # Background image with overlay for better text contrast
    background_image = """
    <style>
    [data-testid="stAppViewContainer"] {
        background-image: linear-gradient(rgba(255, 255, 255, 0.7), rgba(255, 255, 255, 0.7)), 
                          url("https://images.unsplash.com/photo-1639762681057-408e52192e55?q=80&w=2232&auto=format&fit=crop");
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
    }
    
    /* Main content containers */
    .main, .stTabs [data-baseweb="tab-panel"] {
        background-color: rgba(255, 255, 255, 0.95) !important;
        border-radius: 15px !important;
        padding: 2rem !important;
        margin: 1rem 0 !important;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1) !important;
        border: 1px solid #e0e0e0 !important;
    }
    
    /* All text elements */
    h1, h2, h3, h4, h5, h6, p, li, td, th, label, a, .stMarkdown, .stText {
        color: #2c3e50 !important;
        text-shadow: none !important;
    }
    
    /* Links specifically */
    a {
        color: #2980b9 !important;
        text-decoration: underline !important;
        font-weight: bold !important;
    }
    
    a:hover {
        color: #3498db !important;
    }
    
    /* Buttons */
    .stButton>button {
        border: 2px solid #3498db !important;
        border-radius: 20px !important;
        color: white !important;
        background-color: #3498db !important;
        transition: all 0.3s !important;
        font-weight: bold !important;
    }
    
    .stButton>button:hover {
        background-color: #2980b9 !important;
        border-color: #2980b9 !important;
        transform: scale(1.05) !important;
    }
    
    /* Input fields */
    .stTextInput>div>div>input, 
    .stTextArea>div>div>textarea,
    .stSelectbox>div>div>div {
        border-radius: 10px !important;
        border: 1px solid #bdc3c7 !important;
        padding: 10px !important;
        background-color: white !important;
    }
    
    /* Tabs */
    [data-baseweb="tab-list"] {
        gap: 10px !important;
        margin-bottom: 15px !important;
    }
    
    [data-baseweb="tab"] {
        border-radius: 10px !important;
        padding: 10px 20px !important;
        background-color: rgba(255,255,255,0.9) !important;
        transition: all 0.3s !important;
        border: 1px solid #e0e0e0 !important;
    }
    
    [data-baseweb="tab"]:hover {
        background-color: rgba(240, 240, 240, 0.9) !important;
    }
    
    [aria-selected="true"] {
        background-color: #3498db !important;
        color: white !important;
        font-weight: bold !important;
    }
    
    /* Tables and dataframes */
    .stDataFrame, table {
        background-color: white !important;
        border-radius: 10px !important;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1) !important;
    }
    
    /* Expanders */
    .stExpander {
        background-color: white !important;
        border-radius: 10px !important;
        border: 1px solid #e0e0e0 !important;
    }
    
    /* Radio buttons */
    .stRadio>div {
        background-color: white !important;
        padding: 10px !important;
        border-radius: 10px !important;
        border: 1px solid #e0e0e0 !important;
    }
    
    /* Success/error messages */
    .stAlert {
        border-radius: 10px !important;
    }
    </style>
    """
    
    st.markdown(background_image, unsafe_allow_html=True)
    
    # Add subtle animation (less intrusive)
    animated_js = """
    <script>
    document.addEventListener('DOMContentLoaded', () => {
        // Add subtle border animation to main container
        const container = document.querySelector('.main');
        if (container) {
            container.style.boxShadow = '0 0 0 0 rgba(52, 152, 219, 0.7)';
            container.style.transition = 'box-shadow 0.5s ease';
            
            setTimeout(() => {
                container.style.boxShadow = '0 0 0 5px rgba(52, 152, 219, 0)';
            }, 500);
        }
    });
    </script>
    """
    html(animated_js, height=0)

# Call the function to set styles
set_background_and_styles()

# Add header with improved contrast
st.markdown("""
<div style="
    background: linear-gradient(135deg, #3498db, #2c3e50);
    padding: 1.5rem;
    border-radius: 15px;
    color: white !important;
    margin-bottom: 2rem;
    box-shadow: 0 4px 15px rgba(0,0,0,0.2);
">
    <h1 style="color: white !important; margin: 0; text-align: center;">
        🔒 Privilege Escalation Attack Detection and Mitigation
    </h1>
</div>
""", unsafe_allow_html=True)



# Paths to pre-trained models
TFIDF_MODEL_PATH = "models/tfidf_vectorizer.pkl"
SVC_MODEL_PATH = "models/email_classifier.pkl"
USERS_CSV_PATH = "users.csv"
# Load pre-trained models
@st.cache_resource
def load_models():
    try:
        with open(TFIDF_MODEL_PATH, "rb") as tfidf_file, open(SVC_MODEL_PATH, "rb") as svc_file:
            vectorizer = pickle.load(tfidf_file)
            model = pickle.load(svc_file)
        return vectorizer, model
    except FileNotFoundError:
        st.error("Model files not found. Ensure tfidf_vectorizer.pkl and email_classifier.pkl are in 'models' directory.")
        return None, None

vectorizer, model = load_models()

# Initialize users.csv if it doesn't exist
if not os.path.exists(USERS_CSV_PATH):
    pd.DataFrame(columns=["username", "password", "email"]).to_csv(USERS_CSV_PATH, index=False)

# Load users from users.csv
def load_users():
    return pd.read_csv(USERS_CSV_PATH)

# Save a new user to users.csv
def save_user(username, password, email):
    users = load_users()
    if username in users["username"].values or email in users["email"].values:
        return False  # Username or email already exists
    new_user = pd.DataFrame({"username": [username], "password": [password], "email": [email]})
    updated_users = pd.concat([users, new_user], ignore_index=True)
    updated_users.to_csv(USERS_CSV_PATH, index=False)
    return True

# Tabs for interfaces
tab1, tab2, tab3 = st.tabs(["Attacker Interface", "User Interface", "Admin Interface"])

# Attacker Interface
with tab1:
    st.subheader("Attacker Interface")

    # Phishing email inputs
    attacker_sender = st.text_input("Sender Email", value="attacker@fake.com", key="phish_sender")
    attacker_receiver = st.text_input("Receiver Email", value="", key="phish_receiver")
    phishing_subject = st.text_input("Subject", value="Urgent: Verify Your Account", key="phish_subject")
    phishing_body = st.text_input("Body", value="Click here to verify: http://fake-login.com", key="phish_body")
    phishing_url = st.text_input("Phishing URL", value="http://fake-login.com", key="phish_url")

    if st.button("Send Phishing Email"):
        if "emails" not in st.session_state:
            st.session_state.emails = []
        email = {
            "sender": attacker_sender,
            "receiver": attacker_receiver,
            "subject": phishing_subject,
            "body": phishing_body,
            "url": phishing_url
        }
        st.session_state.emails.append(email)
        st.success(f"Phishing email sent to {attacker_receiver}!")
        if st.button("Check for New Credentials"):
            st.info("Refreshing captured credentials...")
            if st.button("Check for New credentials"):
                # Simulate fetching new emails
                fetch_new_creds(captured_creds)  # Function to fetch new emails
                st.rerun()  # Rerun the app to refresh the email display
    # Display captured credentials
    if "captured_creds" in st.session_state and st.session_state.captured_creds:
        st.subheader("Captured Credentials")

    # Add a button to check for new credentials

    
        for idx, creds in enumerate(st.session_state.captured_creds):
            st.write(f"{idx + 1}. Username: {creds['username']}, Password: {creds['password']}, Email: {creds['email']}")
    else:
        st.write("No credentials captured yet.")


# User Interface
# User Interface
with tab2:
    user_action = st.radio(
        "Choose Action", ["Login", "Register", "View Emails", "Send Email to Admin"], key="user_action"
    )

    # Initialize blocklist in session state if not already done
    if "blocklist" not in st.session_state:
        st.session_state.blocklist = []

    # Register User
    if user_action == "Register":
        st.subheader("User Registration")
        username = st.text_input("Choose a Username")
        password = st.text_input("Choose a Password", type="password")
        email = st.text_input("Enter Your Email")
    
        if st.button("Register"):
            # Load the existing users
            users = load_users()
        
            if username in users["username"].values:
                st.error("Username already exists!")
            else:
                # Create a new DataFrame for the new user
                new_user = pd.DataFrame([{"username": username, "password": password, "email": email}])
            
                # Append the new user using pd.concat
                users = pd.concat([users, new_user], ignore_index=True)
            
                # Save the updated DataFrame
                save_user(username=username, password=password, email=email)  # Pass arguments explicitly

                st.success("Registration successful!")

    # Login User
    elif user_action == "Login":
        st.subheader("User Login")
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")

        if st.button("Login as User"):
            users = load_users()  # Load users from the CSV file
            users["username"] = users["username"].astype(str)
            users["password"] = users["password"].astype(str)

            # Authenticate user
            user_row = users.loc[
                (users["username"].str.strip() == username.strip()) & 
                (users["password"].str.strip() == password.strip())
            ]
            if not user_row.empty:
                st.success(f"Logged in as {username}")
                st.session_state.user_logged_in = user_row.iloc[0].to_dict()
            else:
                st.error("Invalid credentials! Please check your username and password.")

    # View Emails
    elif user_action == "View Emails":
        st.subheader("View Emails")
        if "user_logged_in" not in st.session_state:
            st.warning("Please log in to view your emails.")
        else:
            user_email = st.session_state.user_logged_in["email"]
            st.info(f"Your registered email is: {user_email}")
            if st.button("Check for New Mails"):
                # Simulate fetching new emails
                  # Function to fetch new emails
                st.success("Checked for new emails!")
                st.rerun()  # Rerun the app to refresh the email display

            if "emails" not in st.session_state or not st.session_state.emails:
                st.write("No new emails.")
            else:
                user_emails = [
                    email for email in st.session_state.emails 
                    if email["receiver"] == user_email
                ]
                if not user_emails:
                    st.write("No new emails.")
                else:
                    for idx, email in enumerate(user_emails):
                        with st.expander(f"Email {idx + 1}: {email['subject']}"):
                            st.write(f"From: {email['sender']}")
                            st.write(f"Body: {email['body']}")
                            if st.button(f"Click Link in Email {idx + 1}", key=f"phish_link_{idx}"):
                                # Simulate phishing attack
                                if "captured_creds" not in st.session_state:
                                    st.session_state.captured_creds = []
                                st.session_state.captured_creds.append({
                                    "username": st.session_state.user_logged_in["username"],
                                    "password": st.session_state.user_logged_in["password"],
                                    "email": user_email,
                                })
                                st.success("Link clicked! (Redirecting...)")
                                st.warning("You have been redirected to a malicious website!")

    # Send Email to Admin
    elif user_action == "Send Email to Admin":
        st.subheader("Send Email to Admin")
        if "user_logged_in" not in st.session_state:
            st.warning("Please log in to send an email.")
        else:
            user_email = st.session_state.user_logged_in["email"]

            # Check if the user's email is in blocked_users.csv
            def is_user_blocked(email):
                try:
                    blocked_users_df = pd.read_csv("blocked_users.csv")
                    return email in blocked_users_df["Blocked User"].values
                except FileNotFoundError:
                    return False

            if is_user_blocked(user_email):
                st.error("You have been blocked by the admin. Please contact the admin for further details.")
            else:
                st.info(f"Your registered email: {user_email}")

                subject = st.text_input("Email Subject")
                message = st.text_area("Email Message")

                if st.button("Send Email"):
                    if not subject.strip() or not message.strip():
                        st.error("Subject and Message cannot be empty.")
                    else:
                        email = {
                            "sender": user_email,
                            "receiver": "admin@example.com",  # Admin's email
                            "subject": subject.strip(),
                            "body": message.strip(),
                        }
                        if "emails" not in st.session_state:
                            st.session_state.emails = []
                        st.session_state.emails.append(email)
                        st.success("Email sent to admin successfully!")




import pandas as pd
import pickle
import streamlit as st

with tab3:
    st.subheader("Admin Interface")

    # Admin Login
    if "admin_logged_in" not in st.session_state:
        st.session_state.admin_logged_in = False  # Initialize admin login status

    if not st.session_state.admin_logged_in:
        # Admin Login Interface
        st.subheader("Admin Login")
        admin_username = st.text_input("Admin Username")
        admin_password = st.text_input("Admin Password", type="password")

        if st.button("Login as Admin"):
            if admin_username == "lokeshmatha" and admin_password == "loyola":
                st.success("Logged in as Admin")
                st.session_state.admin_logged_in = True  # Set admin login status
                st.rerun()  # Refresh the app to show the Logout button
            else:
                st.error("Invalid admin credentials!")
    else:
        # Admin Interface with Logout Button
        st.success("Logged in as Admin")
        if st.button("Logout"):
            st.session_state.admin_logged_in = False  # Clear admin login status
            st.success("Logged out successfully!")
            st.rerun()  # Refresh the app to show the Login interface


    # Load model and vectorizer
    @st.cache_resource
    def load_model_and_vectorizer():
        with open(r"C:\Users\HP\Documents\my project one\models\email_classifier.pkl", "rb") as model_file:
            model = pickle.load(model_file)
        with open(r"C:\Users\HP\Documents\my project one\models\tfidf_vectorizer.pkl", "rb") as vectorizer_file:
            vectorizer = pickle.load(vectorizer_file)
        return model, vectorizer

    model, vectorizer = load_model_and_vectorizer()

    # Only show this section if the admin is logged in
    if "admin_logged_in" in st.session_state and st.session_state.admin_logged_in:
        st.subheader("Check Emails for Attacks")

        # Initialize session state variables
        if "blocklist" not in st.session_state:
            st.session_state.blocklist = []
        if "read_emails" not in st.session_state:
            st.session_state.read_emails = set()
        if "current_email" not in st.session_state:
            st.session_state.current_email = None
        if "classification_results" not in st.session_state:
            st.session_state.classification_results = {}
        if "log_table" not in st.session_state:
            st.session_state.log_table = []
        if "last_classification_message" not in st.session_state:
            st.session_state.last_classification_message = None

        if "emails" in st.session_state and st.session_state.emails:
            unread_emails = [
                email for email in st.session_state.emails
                if f"{email['sender']}_{email['subject']}" not in st.session_state.read_emails
            ]

            if unread_emails:
                if st.session_state.current_email is None:
                    st.session_state.current_email = unread_emails[0]

                selected_index = st.selectbox(
                    "Select an email to classify",
                    options=range(len(unread_emails)),
                    format_func=lambda i: f"{unread_emails[i]['subject']} (From: {unread_emails[i]['sender']})",
                    key="email_selectbox"
                )
                st.session_state.current_email = unread_emails[selected_index]

                email_to_check = st.session_state.current_email

                with st.expander("Email Details", expanded=True):
                    st.write(f"**From:** {email_to_check['sender']}")
                    st.write(f"**To:** {email_to_check['receiver']}")
                    st.write(f"**Subject:** {email_to_check['subject']}")
                    st.write(f"**Body:** {email_to_check['body']}")
                    if "url" in email_to_check:
                        st.write(f"**URL:** {email_to_check['url']}")

                email_key = f"{email_to_check['sender']}_{email_to_check['subject']}"

                col1, col2 = st.columns([1, 3])
                with col1:
                    if st.button("Check Email for Attack"):
                        email_text = email_to_check["body"]
                        vectorized_text = vectorizer.transform([email_text])
                        prediction = model.predict(vectorized_text)
                        is_attack = "Yes" if prediction[0] == 1 else "No"
                        attack_probability = model.predict_proba(vectorized_text)[0][1] * 100

                        st.session_state.classification_results[email_key] = {
                            "is_attack": is_attack,
                            "attack_probability": attack_probability,
                            "timestamp": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")
                        }

                        st.session_state.read_emails.add(email_key)
                        st.session_state.log_table.append({
                            "Username": email_to_check["sender"],
                            "Subject": email_to_check["subject"],
                            "Body": email_to_check["body"],
                            "Attacked": is_attack,
                            "Attack Probability (%)": f"{attack_probability:.2f}",
                        })

                        if is_attack == "Yes":
                            sender = email_to_check["sender"]
                            if sender not in st.session_state.blocklist:
                                st.session_state.blocklist.append(sender)
                                st.session_state.last_classification_message = f"Escalation: Attack detected in the email! User '{sender}' has been blocked."
                            else:
                                st.session_state.last_classification_message = f"User '{sender}' is already blocked. Escalation: Attack detected!"
                        else:
                            st.session_state.last_classification_message = "The email is safe."

                if email_key in st.session_state.classification_results:
                    results = st.session_state.classification_results[email_key]
                    with col2:
                        st.subheader("Classification Results")
                        st.write(f"**Classification:** {results['is_attack']}")
                        st.write(f"**Attack Probability:** {results['attack_probability']:.2f}%")
                        st.write(f"**Analyzed at:** {results['timestamp']}")

            else:
                st.info("No unread emails available for classification.")

        else:
            st.info("No emails sent by users yet.")

        if st.session_state.last_classification_message:
            st.write(f"**Message:** {st.session_state.last_classification_message}")

        if st.session_state.log_table:
            st.subheader("Email Classification Log")
            log_df = pd.DataFrame(st.session_state.log_table)
            st.dataframe(log_df)
        else:
            st.info("No classifications have been logged yet.")

        # Save blocked users to CSV
        def save_blocklist_to_csv(blocklist, file_path="blocked_users.csv"):
            df = pd.DataFrame(blocklist, columns=["Blocked User"])
            df.to_csv(file_path, index=False)
            st.success(f"Blocked users saved to {file_path}")

        if st.session_state.blocklist:
            st.subheader("Blocked Users")
            for blocked_user in st.session_state.blocklist:
                st.write(f"- {blocked_user}")
            if st.button("Save Blocklist to CSV"):
                save_blocklist_to_csv(st.session_state.blocklist)
        else:
            st.info("No users have been blocked yet.")








