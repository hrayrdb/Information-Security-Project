import customtkinter as ctk
import client

class UserDataFrame(ctk.CTkFrame):
    def __init__(self, parent, username, logout_callback):
        super().__init__(parent)
        self.parent = parent  # Store a reference to the parent
        self.logout_callback = logout_callback  # Store the logout callback
        
        # Fetch user data
        user_data = client.fetch_user_data(username)  # user_data is a list

        # Display user data
        ctk.CTkLabel(self, text="User Data").pack(pady=10)
        ctk.CTkLabel(self, text=f"Username: {user_data[0]}").pack(pady=2)
        ctk.CTkLabel(self, text=f"Phone Number: {user_data[1]}").pack(pady=2)
        ctk.CTkLabel(self, text=f"Address: {user_data[2]}").pack(pady=2)
        ctk.CTkLabel(self, text=f"Project Name: {user_data[3]}").pack(pady=2)

        self.logout_button = ctk.CTkButton(self, text="Logout", command=self.logout)
        self.logout_button.pack(pady=10)

    def logout(self):
        self.logout_callback()
