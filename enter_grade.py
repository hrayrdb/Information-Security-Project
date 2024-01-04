import customtkinter as ctk
import client  # Assuming client.py contains necessary functions

class EnterGradeFrame(ctk.CTkFrame):
    def __init__(self, parent, username, password):
        super().__init__(parent)
        self.username = username
        self.password = password

        # Label for grade entry
        self.grade_label = ctk.CTkLabel(self, text="Enter Grade:")
        self.grade_label.pack(pady=10)

        # Entry for grade
        self.grade_entry = ctk.CTkEntry(self)
        self.grade_entry.pack(pady=10)

        # Submit button
        self.submit_button = ctk.CTkButton(self, text="Submit", command=self.submit_grade)
        self.submit_button.pack(pady=10)

        # Response label
        self.response_label = ctk.CTkLabel(self, text="")
        self.response_label.pack(pady=10)

    def submit_grade(self):
        grade = self.grade_entry.get()
        result = client.csr.generate(self.username)
        if result.startswith("Successful: CSR verification and signing complete."):
            encrypted_grade = client.encrypt(grade.encode("utf-8"))
            client.client_socket.send(encrypted_grade)

            hashed_grade = client.hashing.sha256(grade)
            signed_hashed_grade = client.sign.sign_data(hashed_grade, self.password)
            client.client_socket.send(signed_hashed_grade.encode("utf-8"))

            self.response_label.configure(text="Grade submitted successfully.")
        else:
            self.response_label.configure(text="Could not generate CSR.")
