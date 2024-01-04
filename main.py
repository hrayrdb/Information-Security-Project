import customtkinter as ctk
from main_menu_frame import MainMenuFrame
from create_account_frame import CreateAccountFrame
from login_frame import LoginFrame
from student_add_info import StudentInfoFrame
from student_grad_title import ProjectTitleFrame
from doctor_frame import DoctorMessageFrame

import os
import platform

class App(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("Client Application")
        self.geometry("700x600")

        # Initialize Frames
        self.main_menu_frame = MainMenuFrame(self, self.show_create_account_frame, self.show_login_frame)
        self.create_account_frame = CreateAccountFrame(self, self.show_main_menu)
        self.login_frame = LoginFrame(self, self.show_student_info_frame, self.show_doctor_message_frame, self.show_main_menu)
        self.student_info_frame = StudentInfoFrame(self, self.show_project_title_frame)
        self.project_title_frame = ProjectTitleFrame(self, self.show_main_menu, self.logout)
        self.doctor_message_frame = DoctorMessageFrame(self, self.logout)

        # List of all frames
        self.frames = [self.main_menu_frame, self.create_account_frame, self.login_frame,
                       self.student_info_frame, self.project_title_frame, self.doctor_message_frame]

        # Pack Main Menu Frame initially
        self.main_menu_frame.pack(fill="both", expand=True)

        # Hide other frames initially
        for frame in self.frames:
            if frame is not self.main_menu_frame:
                frame.pack_forget()
                
    def login_success(self):
        self.logged_in = True
        print("Login status: " + str(self.logged_in))
        
    def logout(self):
        # Clear the terminal
        if platform.system() == "Windows":
            os.system('cls')
        else:
            os.system('clear')

        # Set logged_in to False and show the main menu
        self.logged_in = False
        print("Login status: " + str(self.logged_in))
        self.show_frame(self.main_menu_frame)
        
    def show_frame(self, frame):
        # Hide all frames
        for f in self.frames:
            f.pack_forget()
        # Show the requested frame
        frame.pack(fill="both", expand=True)
        frame.tkraise()

    def show_create_account_frame(self):
        self.show_frame(self.create_account_frame)

    def show_login_frame(self):
        self.show_frame(self.login_frame)

    def show_student_info_frame(self):
        self.show_frame(self.student_info_frame)

    def show_project_title_frame(self):
        self.show_frame(self.project_title_frame)

    def show_main_menu(self):
        self.show_frame(self.main_menu_frame)

    def show_doctor_message_frame(self):
        self.show_frame(self.doctor_message_frame)

if __name__ == "__main__":
    app = App()
    app.mainloop()
