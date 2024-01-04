import customtkinter as ctk
from tkinter import ttk, PhotoImage


class LoginFrame(ctk.CTkFrame):
    def __init__(self, parent, show_student_info_callback, show_doctor_message_callback, return_to_main_menu_callback):
        super().__init__(parent)

        self.parent = parent  # Set the parent attribute
        self.show_student_info_callback = show_student_info_callback
        self.show_doctor_message_callback = show_doctor_message_callback
        self.return_to_main_menu_callback = return_to_main_menu_callback 

        
        # Username entry
        ctk.CTkLabel(self, text="Username:").pack(pady=(10, 0))
        self.username_entry = ctk.CTkEntry(self)  # Ensure this matches the attribute used later
        self.username_entry.pack(pady=(0, 10))

        # Password label and entry
        ctk.CTkLabel(self, text="Password:").pack(pady=(0, 0))
        self.password_entry = ctk.CTkEntry(self, show="*")
        self.password_entry.pack(pady=(0, 10))

        # Password Show/Hide Button
        self.password_toggle_btn = ctk.CTkButton(self, text="Show Password", command=self.toggle_password)
        self.password_toggle_btn.pack(pady=(0, 10))
        
        # Login button
        self.button_login = ctk.CTkButton(self, text="Login", command=self.login)
        self.button_login.pack(pady=(0, 5))
        
        # Back button
        ctk.CTkButton(self, text="Back", command=return_to_main_menu_callback).pack(pady=(5, 10))

        # Response label
        self.response_label = ctk.CTkLabel(self, text="")
        self.response_label.pack(pady=10)
        self.response_label.configure(text='')
        
    def toggle_password(self):
        if self.password_entry.cget('show') == "*":
            self.password_entry.configure(show="")
            self.password_toggle_btn.configure(text="Hide Password")
        else:
            self.password_entry.configure(show="*")
            self.password_toggle_btn.configure(text="Show Password")
    
    def login(self):
        import client  # Import your client.py module

        username = self.username_entry.get()  # Use the correct attribute name
        password = self.password_entry.get()  # Use the correct attribute name


        # Call the login function in client.py
        user_type = client.login(username, password)

        # Update response label
        if user_type == "doctor":
            self.response_label.configure(text="Logged in as a doctor")
            self.show_doctor_message_callback()  # Navigate to the doctor message frame
            self.parent.login_success()  # Notify parent of successful login
        elif user_type == "student":
            self.response_label.configure(text="Logged in as a student")
            self.show_student_info_callback()  # Navigate to the student info frame
            self.parent.login_success(username, password)  # Notify parent of successful login
        else:
            self.response_label.configure(text="Login failed. Please try again.")
# Example usage
if __name__ == "__main__":
    root = ctk.CTk()
    login_frame = LoginFrame(root)
    login_frame.pack(fill="both", expand=True)
    root.mainloop()
