import customtkinter as ctk


class StudentInfoFrame(ctk.CTkFrame):
    def __init__(self, parent, show_project_title_callback):
        super().__init__(parent)
        self.parent = parent
        self.show_project_title_callback = show_project_title_callback

        
        # Phone Number
        ctk.CTkLabel(self, text="Phone Number:").pack(pady=(10, 0))
        self.phone_number_entry = ctk.CTkEntry(self)
        self.phone_number_entry.pack(pady=(0, 10))

        # Address
        ctk.CTkLabel(self, text="Address:").pack()
        self.address_entry = ctk.CTkEntry(self)
        self.address_entry.pack(pady=10)

        # Next Button to go to project title frame
        ctk.CTkButton(self, text="Next", command=self.send_info).pack(pady=10)
        self.logout_button = ctk.CTkButton(self, text="Logout", command=self.logout)
        self.logout_button.pack(pady=10)

    def logout(self):
        self.parent.logout()

    def send_info(self):
        import client  # Import your client.py module
        phone_number = self.phone_number_entry.get()
        address = self.address_entry.get()
        response = client.send_student_info(phone_number, address)
        if response.startswith("Successful"):
            self.show_project_title_callback()
        else:
            # Handle error response
            pass