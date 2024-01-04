import customtkinter as ctk


class ProjectTitleFrame(ctk.CTkFrame):
    def __init__(self, parent, return_to_main_menu_callback, logout_callback):
        super().__init__(parent)
        self.parent = parent  # Store a reference to the parent
        self.logout_callback = logout_callback  # Store the logout callback
        self.return_to_main_menu_callback = return_to_main_menu_callback

        # Graduation Project Title
        ctk.CTkLabel(self, text="Graduation Project Title:").pack(pady=(10, 0))
        self.project_title_entry = ctk.CTkEntry(self)
        self.project_title_entry.pack(pady=(0, 10))

        # Submit Button
        ctk.CTkButton(self, text="Submit", command=self.submit_project_title).pack(pady=10)
        self.logout_button = ctk.CTkButton(self, text="Logout", command=self.logout)
        self.logout_button.pack(pady=10)
        
        # Response Label
        self.response_label = ctk.CTkLabel(self, text="")
        self.response_label.pack(pady=10)
        self.response_label.configure(text='')
        
    def logout(self):
        self.logout_callback()
        
    def submit_project_title(self):
        import client  # Import your client.py module
        project_title = self.project_title_entry.get()
        response = client.send_project_title(project_title)
        self.response_label.configure(text=response)
