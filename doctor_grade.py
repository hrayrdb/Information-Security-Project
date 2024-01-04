import customtkinter as ctk
import client  # Import your client.py module
import threading

class DoctorGradeFrame(ctk.CTkFrame):
    def __init__(self, parent, logout_callback, show_enter_grade_frame_callback):
        super().__init__(parent)
        self.parent = parent
        self.logout_callback = logout_callback
        self.show_enter_grade_frame_callback = show_enter_grade_frame_callback

        # Create UI elements
        self.setup_ui()

    def setup_ui(self):
        # Doctor Message Label
        self.message_label = ctk.CTkLabel(self, text="Doctor Grade Submission", font=("Arial", 14))
        self.message_label.pack(pady=10)

        # CSR Generation Button
        self.csr_button = ctk.CTkButton(self, text="Generate CSR", command=self.generate_csr)
        self.csr_button.pack(pady=10)

        # Logout Button
        self.logout_button = ctk.CTkButton(self, text="Logout", command=self.logout)
        self.logout_button.pack(pady=10)

        # Response Label
        self.response_label = ctk.CTkLabel(self, text="")
        self.response_label.pack(pady=10)

    def generate_csr(self):
        # Run CSR generation in a separate thread
        threading.Thread(target=self.run_csr_generation, daemon=True).start()

    def run_csr_generation(self):
        # Call the generate function and capture the response
        response = client.csr.generate(str(self.parent.username))  # Assuming username is stored in parent
        if response.startswith("Successful: CSR verification and signing complete."):
            self.show_enter_grade_frame_callback()
        else:
            self.response_label.configure(text=response)

    def logout(self):
        self.logout_callback()
