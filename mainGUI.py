import PySimpleGUI as sg
import os
from schnorr import create_key, sign_docs, verify_docs

t1_layout = [[sg.Button(button_text='Tạo khóa mới', key='-genkey-', )]]

t2_layout = [[sg.Text('Chọn tệp tin'), sg.In('Đường dẫn đến tệp tin', key='-pathfilesign-'), sg.FileBrowse('Chọn tệp', key='-file2sign-')], [sg.Button('Ký', key='-sign-')]]

t3_layout = [[sg.T('Chọn tệp tin'), sg.In('Đường dẫn đến tệp tin', key='-pathfileverify-'), sg.FileBrowse('Chọn tệp', key='-file2verify-')], [sg.Button('Xác thực', key='-verify-')]]

layout = [[sg.TabGroup([[sg.Tab('Tạo khóa', t1_layout, tooltip='Tạo khóa'), sg.Tab('Ký tệp tin', t2_layout, tooltip='Ký file'), sg.Tab('Xác minh chữ ký', t3_layout, tooltip='Xác thực')]])],
 [sg.Button('Thoát', key='-exit-')]]

window = sg.Window('Sơ đồ Schnorr', layout=layout)

while True:
    event, value = window.read()

    if event in [sg.WIN_CLOSED, '-exit-']:
        break
    
    # print(value)
    # print(event)
    if event =='-genkey-':
        if not os.path.isfile(os.path.join('Keys', 'Private.key')) or not os.path.isdir('Keys'):
            create_key()
            sg.popup('Tạo khóa thành công')
        elif os.path.isfile(os.path.join('Keys', 'Private.key')):
            a = sg.popup_ok_cancel('Khóa đã tồn tại, ghi đè?')
            if a == 'OK':
                create_key()
                b = sg.popup('Tạo khóa mới thành công')
                print(b)
    elif event == '-sign-':
        if os.path.isfile(value['-pathfilesign-']) or os.path.isfile(value['-file2sign-']):
            ret = sign_docs(value['-pathfilesign-'])
            if ret == 0:
                sg.popup('Ký thành công')
            elif ret == -1:
                sg.popup('Khóa không tồn tại, tạo khóa trước khi ký')
            else:
                sg.popup('Không thể ký với khóa hiện tại')
            pass
        else:
            sg.popup('Không phải tệp tin')
    elif event == '-verify-':
        if os.path.isfile(value['-pathfileverify-']) or os.path.isfile(value['-file2verify-']):
            if verify_docs(value['-pathfileverify-']):
                sg.popup('Tệp tin xác thực')
            else:
                sg.popup('Không thể xác thực tệp tin')
        else:
            sg.popup('Xin nhập đúng đường dẫn đến file cần xác thực')
        pass
window.close()
