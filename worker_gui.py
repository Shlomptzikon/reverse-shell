import flet as ft
from flet.core.types import FontWeight

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
        self.password_input = ft.TextField(label="enter password", filled=True, border=ft.InputBorder.UNDERLINE, on_change=self.check_password)
        self.validate_password = ft.Text("password must be at least 12 characters and contain at least: one special character, one digit and one capital letter.")
        self.success = ft.Text()
        self.submit_button = ft.OutlinedButton(text="submit", on_click=self.submitted,disabled=True)
        self.update_button = ft.OutlinedButton(text="update",on_click=self.updated,disabled=True)
        ip = "10.0.0.9"
        port = 5555
        self.worker = Worker(ip,port)

    def updated(self,e):
        if self.username_input.value == "" or self.password_input.value == "":
            return
        msg = self.worker.update_user(self.username_input.value,self.password_input.value)
        self.success.value = msg
        self.page.update()
    def submitted(self,e):
        if self.username_input.value == "" or self.password_input.value == "":
            return
        msg = self.worker.sign_up(self.username_input.value,self.password_input.value)
        self.success.value = msg
        self.submit_button.disabled = True
        self.update_button.disabled = False
        self.page.update()
    def check_password(self,e):
        pass

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
        self.worker.run()

ft.app(App().main)
