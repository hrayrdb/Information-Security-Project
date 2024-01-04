import customtkinter as ctk
# import client  # Import your client.py module

class DoctorMessageFrame(ctk.CTkFrame):
    def __init__(self, parent, logout_callback):
        super().__init__(parent)
        self.parent = parent  # Store a reference to the parent
        self.logout_callback = logout_callback  # Store the logout callback
        

        self.message_label = ctk.CTkLabel(self, text="YOU ARE A DOCTOR", font=("Arial", 14))
        self.message_label.pack(pady=20)
        self.logout_button = ctk.CTkButton(self, text="Logout", command=self.logout)
        self.logout_button.pack(pady=10)

    def logout(self):
        self.logout_callback()