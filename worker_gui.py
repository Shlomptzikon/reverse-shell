import flet as ft
from flet.core.types import FontWeight
import re

from numpy.ma.core import correlate
from sympy import content
from sympy.physics.units import current

from mysql.components import field
from rs_worker import Worker

class App:
    def __init__(self):
        self.page: ft.Page | None = None
        self.title = ft.Container(
            content=ft.Text("Register", size=40, italic=True, weight=FontWeight.BOLD),
            alignment=ft.alignment.top_center,
            bgcolor=ft.Colors.AMBER,
            margin=10,
            padding=10,
            border_radius=10
        )
        self.username_input = ft.TextField(label="enter user name", filled=True,border=ft.InputBorder.UNDERLINE)
        self.password_input = ft.TextField(label="enter password", filled=True, border=ft.InputBorder.UNDERLINE, on_change=self.check_password, password=True, can_reveal_password=True)
        self.validate_password = ft.Text("password must be at least 12 characters and contain at least: one special character, one digit and one capital letter.", color=ft.Colors.RED)
        self.validated = False
        self.success = ft.Text()
        self.submit_button = ft.OutlinedButton(text="submit", on_click=self.submitted,disabled=True)
        self.update_button = ft.OutlinedButton(text="update",on_click=self.updated,disabled=True)
        ip = "10.0.0.10"
        port = 5555
        self.worker = Worker(ip,port)
        self.new_admin_pas = ft.TextField(label="new password",
                                          filled=True,
                                          border=ft.InputBorder.UNDERLINE,
                                          on_change=self.check_password,
                                          password=True,
                                          can_reveal_password=True,
                                          disabled=True)
        self.enter_admin = ft.AlertDialog(title="please enter new password for the admin user",
                                          content=ft.Column(
                                              [
                                                  ft.TextField(label="current password", filled=True,
                                                               border=ft.InputBorder.UNDERLINE,
                                                               on_change=self.check_admin, password=True,
                                                               can_reveal_password=True),
                                                  self.new_admin_pas,
                                                  self.validate_password,

                                              ],
                                              tight=True,
                                              spacing=10,
                                              horizontal_alignment=ft.CrossAxisAlignment.CENTER
                                          ),
                                          actions=[
                                              ft.OutlinedButton(text="submit", on_click=self.submit_admin, )
                                          ],
                                          modal=True,

                                          )
    def on_window_event(self,e):
        if e.data == "close":
            self.worker.stop_run = True

    def check_admin(self,e):
        if self.worker.check_admin(e.control.value):
            self.new_admin_pas.disabled = False
        else:
            self.new_admin_pas.enabled = True
        self.page.update(self.enter_admin)
    def submit_admin(self,e):
        if self.new_admin_pas.value == "" or self.validated == False:
            return
        self.worker.update_admin(self.new_admin_pas.value)
        self.page.close(self.enter_admin)
    def updated(self,e):
        if self.username_input.value == "" or self.password_input.value == "" or self.validated == False:
            return
        msg = self.worker.update(self.username_input.value,self.password_input.value)
        self.success.value = msg
        self.page.update()
    def submitted(self,e):
        if self.username_input.value == "" or self.password_input.value == "": #or self.validated == False:
            return
        msg = self.worker.sign_up(self.username_input.value,self.password_input.value)
        self.success.value = msg
        if "success" in msg:
            self.submit_button.disabled = True
            self.update_button.disabled = False
        self.page.update()
    def check_password(self,e):
        correct_len= "be at least 12 characters and"
        cap = "one capital letter"
        special = "one special character,"
        digit = "one digit,"
        current_password = e.control.value
        if len(current_password) >= 12:
            correct_len = ""
        if re.search(r'[A-Z]',current_password):
            cap = ""
        if re.search(r'\d',current_password):
            digit = ""
        if re.search(r'[^\w\s]',current_password):
            special = ""
        if (not correct_len) and (not cap) and (not digit) and (not special):
            self.validate_password.value = "nice password"
            self.validate_password.color = ft.Colors.GREEN
            self.validated = True
        else:
            self.validate_password.value = f"password must {correct_len} contain: {special} {digit} {cap}"
            self.validate_password.color = ft.Colors.RED
            self.validated = False

        self.page.update()


    def main(self, page:ft.Page):
        self.page = page
        if self.worker.is_empty():
            self.submit_button.disabled = False
        else:
            self.update_button.disabled = False

        self.page.add(
            self.title,
            ft.Column(
                [
                    self.username_input,
                    self.password_input,
                    self.validate_password,
                    ft.Row(
                        [
                            self.submit_button,
                            self.update_button
                        ]
                    ),
                    self.success
                ]
            )
        )
        if self.worker.check_admin("admin"):
            self.page.open(self.enter_admin)
    #    self.worker.run()

ft.app(App().main)
