import customtkinter as ctk
from tkinter import ttk
from tkinter import ttk, PhotoImage

class CreateAccountFrame(ctk.CTkFrame):
    def __init__(self, parent, return_to_main_menu_callback):
        super().__init__(parent)
        self.return_to_main_menu_callback = return_to_main_menu_callback 
        
        # Username label and entry
        ctk.CTkLabel(self, text="Username:").pack(pady=(10, 0))
        self.username_entry = ctk.CTkEntry(self)
        self.username_entry.pack(pady=(0, 10))

        # Password label and entry
        ctk.CTkLabel(self, text="Password:").pack(pady=(0, 0))
        self.password_entry = ctk.CTkEntry(self, show="*")
        self.password_entry.pack(pady=(0, 10))

        # Password Show/Hide Button
        self.password_toggle_btn = ctk.CTkButton(self, text="Show Password", command=self.toggle_password)
        self.password_toggle_btn.pack(pady=(0, 10))

        # User type label and dropdown
        ctk.CTkLabel(self, text="User Type:").pack(pady=(0, 0))
        self.user_type_var = ctk.StringVar()
        self.user_type_dropdown = ttk.Combobox(self, textvariable=self.user_type_var, values=["doctor", "student"])
        self.user_type_dropdown.pack(pady=(0, 10))

        # Create account button
        ctk.CTkButton(self, text="Create", command=self.create_account).pack(pady=(0, 5))

        # Back button
        ctk.CTkButton(self, text="Back", command=return_to_main_menu_callback).pack(pady=(5, 10))

        # Response label
        
        self.response_label = ctk.CTkLabel(self)
        self.response_label.pack(pady=10)
        self.response_label.configure(text='')
        
    def toggle_password(self):
        if self.password_entry.cget('show') == "*":
            self.password_entry.configure(show="")
            self.password_toggle_btn.configure(text="Hide Password")
        else:
            self.password_entry.configure(show="*")
            self.password_toggle_btn.configure(text="Show Password")
            
    def create_account(self):
        import client
        username = self.username_entry.get()
        password = self.password_entry.get()
        user_type = self.user_type_var.get()

        response = client.create_account(username, password, user_type)  # Call the function from client.py

        self.response_label.configure(text=response)
        if response.startswith("Successful"):
            self.return_to_main_menu_callback()  # Use the callback to navigate back to main menu
