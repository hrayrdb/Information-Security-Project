import customtkinter as ctk
import client  # Import the client module

class DoctorMessageFrame(ctk.CTkFrame):
    def __init__(self, parent, logout_callback, show_doctor_grade_callback):
        super().__init__(parent)
        self.parent = parent
        self.logout_callback = logout_callback
        self.show_doctor_grade_callback = show_doctor_grade_callback  # Added callback for showing doctor grade frame

        # Generate math problem
        self.math_problem, self.correct_answer = client.generate_math_problem()

        # Math Problem Label
        self.math_problem_label = ctk.CTkLabel(self, text=f"Math Problem: {self.math_problem}", font=("Arial", 14))
        self.math_problem_label.pack(pady=10)

        # Answer Entry
        self.answer_entry = ctk.CTkEntry(self)
        self.answer_entry.pack(pady=10)

        # Submit Answer Button
        self.submit_button = ctk.CTkButton(self, text="Submit Answer", command=self.submit_answer)
        self.submit_button.pack(pady=10)

        # Response Label
        self.response_label = ctk.CTkLabel(self, text="", font=("Arial", 12))
        self.response_label.pack(pady=10)

        # Logout Button
        self.logout_button = ctk.CTkButton(self, text="Logout", command=self.logout)
        self.logout_button.pack(pady=10)

    def submit_answer(self):
        user_answer = self.answer_entry.get()
        if client.verify_math_answer(user_answer, self.correct_answer):
            response = "Correct answer! Identity verified."
            self.show_doctor_grade_callback()  # Navigate to doctor grade frame
        else:
            response = "Incorrect answer. Identity verification failed."
        self.response_label.configure(text=response)

    def logout(self):
        self.logout_callback()
