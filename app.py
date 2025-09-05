# pip install streamlit pyyaml bcrypt streamlit-autorefresh

import streamlit as st
import yaml
import os
import bcrypt
from datetime import datetime
from streamlit_autorefresh import st_autorefresh

# ====================
# File paths
# ====================
USER_DB = "users.yaml"
CHAT_DB = "chat.yaml"

# ====================
# Helpers
# ====================
def load_yaml(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            data = yaml.safe_load(f)
            return data if isinstance(data, dict) else {}
    return {}

def save_yaml(path, data):
    with open(path, "w") as f:
        yaml.safe_dump(data, f)

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False

def rerun_now():
    # Works on new and older Streamlit
    fn = getattr(st, "rerun", None) or getattr(st, "experimental_rerun", None)
    if fn:
        fn()

# ====================
# Authentication
# ====================
def signup(username, password):
    users = load_yaml(USER_DB)
    if not username or not password:
        return False, "Username and password are required."
    if username in users:
        return False, "Username already exists."
    users[username] = {"password": hash_password(password)}
    save_yaml(USER_DB, users)
    return True, "Signup successful! Please log in."

def login(username, password):
    users = load_yaml(USER_DB)
    if username not in users:
        return False, "User not found."
    if not verify_password(password, users[username]["password"]):
        return False, "Invalid password."
    return True, "Login successful!"

# ====================
# Messaging
# ====================
def _ensure_chat_struct(chats):
    if "private" not in chats:
        chats["private"] = {}
    if "group" not in chats:
        chats["group"] = []
    return chats

def send_private_message(sender, receiver, message):
    chats = load_yaml(CHAT_DB)
    chats = _ensure_chat_struct(chats)
    chats["private"].setdefault(sender, [])
    chats["private"].setdefault(receiver, [])
    msg = {
        "from": sender,
        "to": receiver,
        "message": message,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    chats["private"][sender].append(msg)
    chats["private"][receiver].append(msg)
    save_yaml(CHAT_DB, chats)

def get_private_chat(user1, user2):
    chats = load_yaml(CHAT_DB)
    chats = _ensure_chat_struct(chats)
    msgs = chats["private"].get(user1, [])
    return [m for m in msgs if (m["from"] == user2 or m["to"] == user2)]

def send_group_message(sender, message):
    chats = load_yaml(CHAT_DB)
    chats = _ensure_chat_struct(chats)
    msg = {
        "from": sender,
        "message": message,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    chats["group"].append(msg)
    save_yaml(CHAT_DB, chats)

def get_group_chat():
    chats = load_yaml(CHAT_DB)
    chats = _ensure_chat_struct(chats)
    return chats["group"]

# ====================
# UI
# ====================
st.set_page_config(page_title="Chat App", page_icon="💬", layout="centered")
st.title("💬 Real-Time Messaging App")

# Session state
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = None

# ==== Auth (Tabs) ====
if not st.session_state.logged_in:
    tab_login, tab_signup = st.tabs(["🔑 Login", "📝 Signup"])

    with tab_login:
        st.subheader("Login to your account")
        user = st.text_input("Username", key="login_user")
        pw = st.text_input("Password", type="password", key="login_pw")
        if st.button("Login", type="primary", key="login_btn"):
            success, msg = login(user, pw)
            if success:
                st.session_state.logged_in = True
                st.session_state.username = user
                st.success(msg)
                rerun_now()
            else:
                st.error(msg)

    with tab_signup:
        st.subheader("Create Account")
        new_user = st.text_input("Username", key="signup_user")
        new_pass = st.text_input("Password", type="password", key="signup_pw")
        if st.button("Signup", key="signup_btn"):
            ok, msg = signup(new_user, new_pass)
            (st.success if ok else st.error)(msg)

# ==== Chat ====
else:
    # Optional: Logout for convenience
    with st.sidebar:
        st.success(f"Logged in as {st.session_state.username}")
        if st.button("Logout", key="logout_btn"):
            st.session_state.logged_in = False
            st.session_state.username = None
            rerun_now()
        st.write("please make sure you don't refresh the app when youre having a chat, you will be logged out if you do that because the app is under development")

        chat_mode = st.radio("Choose chat mode:", ["👤 Private Chat", "👥 Group Chat"])

    # Auto-refresh every 3 seconds
    st_autorefresh(interval=3000, key="chat_refresh")

    if chat_mode == "👤 Private Chat":
        st.subheader("🔒 Private Chat")
        users = load_yaml(USER_DB)
        other_users = sorted([u for u in users if u != st.session_state.username])

        if not other_users:
            st.info("No other users available yet.")
        else:
            receiver = st.selectbox("Chat with:", other_users, key="receiver_select")

            # Chat history
            chat_history = get_private_chat(st.session_state.username, receiver)
            st.markdown("### Chat History")
            if chat_history:
                for msg in chat_history[-20:]:
                    sender = "🟢 You" if msg["from"] == st.session_state.username else f"🔵 {msg['from']}"
                    st.markdown(f"**{sender}:** {msg['message']}  \n*({msg['time']})*")
            else:
                st.info("No messages yet.")

            # Send message
            message = st.text_input("Type your message:", key="private_box")
            if st.button("Send", key="private_send"):
                if message.strip():
                    send_private_message(st.session_state.username, receiver, message)
                    rerun_now()

    else:
        st.subheader("🌍 Group Chat Room")

        # Chat history
        group_history = get_group_chat()
        st.markdown("### Messages")
        if group_history:
            for msg in group_history[-40:]:
                sender = "🟢 You" if msg["from"] == st.session_state.username else f"🔵 {msg['from']}"
                st.markdown(f"**{sender}:** {msg['message']}  \n*({msg['time']})*")
        else:
            st.info("No group messages yet.")

        # Send message
        group_message = st.text_input("Type your message:", key="group_box")
        if st.button("Send", key="group_send"):
            if group_message.strip():
                send_group_message(st.session_state.username, group_message)
                rerun_now()
