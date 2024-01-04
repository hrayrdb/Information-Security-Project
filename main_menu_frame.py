import customtkinter as ctk
from tkinter import ttk
class MainMenuFrame(ctk.CTkFrame):
    def __init__(self, parent, show_create_callback, show_login_callback):
        super().__init__(parent)

        ctk.CTkButton(self, text="Create Account", command=show_create_callback).pack(pady=10)
        ctk.CTkButton(self, text="Login", command=show_login_callback).pack(pady=10)
        ctk.CTkButton(self, text="Exit", command=self.quit).pack(pady=10)
