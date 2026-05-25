import argparse
import base64
import ipaddress
import json
import re
import socket
import struct
import sys
import zlib
from pathlib import Path


BASE_NAME = 'NewConfig'
EXTENSION = '.conf'
LINK_BASE_NAME = 'NewLink'
LINK_EXTENSION = '.txt'
WINDOW_WIDTH = 500
WINDOW_HEIGHT = 330
APP_TITLE = 'Декодер AmneziaVPN'


def script_dir():
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def q_uncompress(data):
    if len(data) < 4:
        return b''

    uncompressed_size = struct.unpack('>I', data[:4])[0]
    compressed_data = data[4:]
    try:
        uncompressed_data = zlib.decompress(compressed_data)
    except zlib.error:
        return b''

    if len(uncompressed_data) != uncompressed_size:
        return b''
    return uncompressed_data


def q_compress(data, level=-1):
    compressed = zlib.compress(data, level)
    header = struct.pack('>I', len(data))
    return header + compressed


def base64url_decode(data):
    padding_needed = (4 - len(data) % 4) % 4
    data += b'=' * padding_needed
    return base64.urlsafe_b64decode(data)


def base64url_encode(data):
    encoded = base64.urlsafe_b64encode(data)
    return encoded.rstrip(b'=')


def decode_vpn_payload(vpn_link):
    data = vpn_link.strip().replace('vpn://', '', 1)
    compressed = base64url_decode(data.encode('ascii'))
    uncompressed = q_uncompress(compressed)
    result = uncompressed if uncompressed else compressed
    return result.decode('utf-8')


def is_ip_address(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def resolve_dns_to_ip(dns_name):
    try:
        return socket.gethostbyname(dns_name)
    except socket.gaierror:
        return None


def process_conf_data(data):
    def replace_endpoint(match):
        full_line = match.group(0)
        prefix = match.group(1)
        address = match.group(2)
        port = match.group(3)
        suffix = match.group(4)
        if is_ip_address(address):
            return full_line

        resolved_ip = resolve_dns_to_ip(address)
        if not resolved_ip:
            raise ValueError(f'Не удалось преобразовать DNS-имя в IP: {address}')
        return f'{prefix}{resolved_ip}:{port}{suffix}'

    pattern = r'^(.*Endpoint\s*=\s*)([^\s:]+)(?::(\d+))(.*)$'
    return re.sub(pattern, replace_endpoint, data, flags=re.MULTILINE)


def encode_config_text(config_text):
    processed_data = process_conf_data(config_text)
    compressed = q_compress(processed_data.encode('utf-8'), level=8)
    return 'vpn://' + base64url_encode(compressed).decode('ascii')


def first_present(*values):
    for value in values:
        if value is not None and value != '':
            return value
    return None


def normalize_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if isinstance(value, str):
        return [part.strip() for part in value.split(',') if part.strip()]
    return [str(value)]


def parse_json_object(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return parsed
    return {}


def select_amnezia_container(data):
    containers = data.get('containers')
    if not isinstance(containers, list):
        return {}

    default_name = data.get('defaultContainer')
    for container in containers:
        if isinstance(container, dict) and container.get('container') == default_name:
            return container

    for container in containers:
        if isinstance(container, dict) and 'awg' in container:
            return container

    return containers[0] if containers and isinstance(containers[0], dict) else {}


def collect_config_data(data):
    container = select_amnezia_container(data)
    awg = parse_json_object(container.get('awg'))
    nested = parse_json_object(awg.get('last_config'))

    merged = {}
    for source in (data, awg, nested):
        if isinstance(source, dict):
            merged.update(source)
    return merged


def append_kv(lines, key, value):
    if value is not None and value != '':
        lines.append(f'{key} = {value}')


def build_amneziawg_conf(data):
    cfg = collect_config_data(data)

    private_key = first_present(cfg.get('client_priv_key'), cfg.get('private_key'), cfg.get('PrivateKey'))
    address = first_present(cfg.get('client_ip'), cfg.get('address'), cfg.get('Address'))
    if address and '/' not in str(address):
        address = f'{address}/32'

    dns_values = []
    for key in ('dns1', 'dns2'):
        value = cfg.get(key)
        if value:
            dns_values.append(str(value))
    if not dns_values:
        dns_values = normalize_list(first_present(cfg.get('dns'), cfg.get('DNS')))

    endpoint_host = first_present(cfg.get('hostName'), cfg.get('host'), cfg.get('server_host'))
    endpoint_port = first_present(cfg.get('port'), cfg.get('server_port'))
    endpoint = first_present(cfg.get('endpoint'), cfg.get('Endpoint'))
    if not endpoint and endpoint_host and endpoint_port:
        endpoint = f'{endpoint_host}:{endpoint_port}'

    allowed_ips = normalize_list(first_present(cfg.get('allowed_ips'), cfg.get('AllowedIPs')))
    if not allowed_ips:
        allowed_ips = ['0.0.0.0/0']

    lines = ['[Interface]']
    append_kv(lines, 'PrivateKey', private_key)
    append_kv(lines, 'Address', address)
    if dns_values:
        append_kv(lines, 'DNS', ', '.join(dns_values))
    append_kv(lines, 'MTU', cfg.get('mtu'))

    awg_keys = ('Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5')
    for key in awg_keys:
        append_kv(lines, key, cfg.get(key))

    lines.append('')
    lines.append('[Peer]')
    append_kv(lines, 'PublicKey', first_present(cfg.get('server_pub_key'), cfg.get('public_key'), cfg.get('PublicKey')))
    append_kv(lines, 'PresharedKey', first_present(cfg.get('psk_key'), cfg.get('preshared_key'), cfg.get('PresharedKey')))
    append_kv(lines, 'Endpoint', endpoint)
    append_kv(lines, 'AllowedIPs', ', '.join(allowed_ips))
    append_kv(lines, 'PersistentKeepalive', first_present(cfg.get('persistent_keep_alive'), cfg.get('PersistentKeepalive')))

    return '\n'.join(lines).rstrip() + '\n'


def extract_config(decoded_data):
    stripped = decoded_data.strip()
    if not stripped.startswith('{'):
        return decoded_data

    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return decoded_data

    if isinstance(data, dict) and 'containers' in data:
        return build_amneziawg_conf(data)

    config = data.get('config') if isinstance(data, dict) else None
    if isinstance(config, str) and config.strip().startswith('[Interface]'):
        return config

    return decoded_data


def decode_vpn_link(vpn_link):
    return extract_config(decode_vpn_payload(vpn_link))


def next_named_path(base_name, extension):
    folder = script_dir()
    first = folder / f'{base_name}{extension}'
    if not first.exists():
        return first

    index = 1
    while True:
        candidate = folder / f'{base_name}_{index}{extension}'
        if not candidate.exists():
            return candidate
        index += 1


def next_config_path():
    return next_named_path(BASE_NAME, EXTENSION)


def next_link_path():
    return next_named_path(LINK_BASE_NAME, LINK_EXTENSION)


def save_config(vpn_link):
    if not vpn_link or not vpn_link.strip():
        raise ValueError('Ссылка пустая. Вставьте ссылку, которая начинается с vpn://')
    if not vpn_link.strip().lower().startswith('vpn://'):
        raise ValueError('Ссылка должна начинаться с vpn://')

    config = decode_vpn_link(vpn_link)
    output_path = next_config_path()
    output_path.write_text(config, encoding='utf-8', newline='\n')
    return output_path


def save_vpn_link_from_config(config_path):
    config_path = Path(config_path)
    config_text = config_path.read_text(encoding='utf-8')
    vpn_link = encode_config_text(config_text)
    output_path = next_link_path()
    output_path.write_text(vpn_link + '\n', encoding='utf-8', newline='\n')
    return output_path


def center_window(root, width, height):
    root.update_idletasks()
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = max((screen_width - width) // 2, 0)
    y = max((screen_height - height) // 2, 0)
    root.geometry(f'{width}x{height}+{x}+{y}')


def show_missing_tkinter_message():
    message = (
        'Не найден стандартный модуль tkinter, который нужен для окна ввода.\n\n'
        'Дополнительные pip-библиотеки для этого скрипта не нужны.\n'
        'tkinter обычно устанавливается вместе с Python для Windows.\n\n'
        'Что сделать:\n'
        '1. Откройте установщик Python.\n'
        '2. Выберите Modify.\n'
        '3. Включите Tcl/Tk and IDLE.\n'
        '4. Запустите этот декодер снова.'
    )

    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(None, message, APP_TITLE, 0x10)
    except Exception:
        print(message, file=sys.stderr)


def ask_link_gui():
    try:
        import tkinter as tk
        from tkinter import filedialog
        from tkinter import scrolledtext
    except ModuleNotFoundError:
        show_missing_tkinter_message()
        raise

    result = {'value': None}

    root = tk.Tk()
    root.title(APP_TITLE)
    root.configure(bg='white')
    root.minsize(WINDOW_WIDTH, WINDOW_HEIGHT)
    center_window(root, WINDOW_WIDTH, WINDOW_HEIGHT)

    label = tk.Label(
        root,
        text='Вставьте ссылку vpn://',
        bg='white',
        fg='black',
        font=('Segoe UI', 11, 'bold'),
    )
    label.pack(anchor='w', padx=14, pady=(12, 6))

    text = scrolledtext.ScrolledText(
        root,
        height=9,
        wrap='word',
        bg='black',
        fg='#ffd84d',
        insertbackground='#ffd84d',
        selectbackground='#335c99',
        selectforeground='white',
        relief='solid',
        borderwidth=1,
        font=('Consolas', 10),
    )
    text.pack(fill='both', expand=True, padx=14)
    text.focus_set()

    def get_clipboard_text():
        try:
            return root.clipboard_get().strip()
        except tk.TclError:
            return ''

    def paste_from_clipboard(replace=False):
        clipboard_text = get_clipboard_text()
        if not clipboard_text:
            root.bell()
            return 'break'

        if replace:
            text.delete('1.0', 'end')
        text.insert('insert', clipboard_text)
        text.focus_set()
        return 'break'

    def auto_paste_from_clipboard():
        clipboard_text = get_clipboard_text()
        field_is_empty = not text.get('1.0', 'end').strip()
        if clipboard_text.lower().startswith('vpn://') and field_is_empty:
            text.insert('1.0', clipboard_text)
            text.focus_set()

    context_menu = tk.Menu(root, tearoff=False)
    context_menu.add_command(label='Вставить', command=lambda: paste_from_clipboard())
    context_menu.add_command(label='Очистить', command=lambda: text.delete('1.0', 'end'))

    def show_context_menu(event):
        context_menu.tk_popup(event.x_root, event.y_root)
        return 'break'

    text.bind('<Control-v>', lambda _event: paste_from_clipboard())
    text.bind('<Control-V>', lambda _event: paste_from_clipboard())
    text.bind('<Shift-Insert>', lambda _event: paste_from_clipboard())
    text.bind('<Button-3>', show_context_menu)
    root.bind('<Control-v>', lambda _event: paste_from_clipboard())
    root.bind('<Control-V>', lambda _event: paste_from_clipboard())
    root.bind('<Shift-Insert>', lambda _event: paste_from_clipboard())
    root.after(150, auto_paste_from_clipboard)

    footer = tk.Label(
        root,
        text='Дополнительные библиотеки устанавливать не нужно.',
        bg='white',
        fg='#555555',
        font=('Segoe UI', 8),
    )
    footer.pack(anchor='w', padx=14, pady=(6, 0))

    buttons = tk.Frame(root, bg='white')
    buttons.pack(fill='x', padx=14, pady=10)

    def submit():
        result['value'] = text.get('1.0', 'end').strip()
        root.destroy()

    def cancel():
        root.destroy()

    def encode_conf_file():
        config_path = filedialog.askopenfilename(
            parent=root,
            title='Выберите файл .conf',
            filetypes=(('WireGuard config', '*.conf'), ('Все файлы', '*.*')),
        )
        if not config_path:
            return

        try:
            output_path = save_vpn_link_from_config(config_path)
        except Exception as exc:
            show_gui_message('error', APP_TITLE, str(exc))
            return

        show_gui_message('info', APP_TITLE, f'Ссылка сохранена:\n{output_path}')

    decode_button = tk.Button(buttons, text='Создать conf', width=14, command=submit)
    decode_button.pack(side='right')

    cancel_button = tk.Button(buttons, text='Отмена', width=10, command=cancel)
    cancel_button.pack(side='right', padx=(0, 8))

    paste_button = tk.Button(buttons, text='Вставить', width=10, command=lambda: paste_from_clipboard(replace=True))
    paste_button.pack(side='left')

    encode_button = tk.Button(buttons, text='AmneziaWG -> AmneziaVPN', width=24, command=encode_conf_file)
    encode_button.pack(side='left', padx=(8, 0))

    root.bind('<Control-Return>', lambda _event: submit())
    root.bind('<Escape>', lambda _event: cancel())
    root.mainloop()

    return result['value']


def show_gui_message(kind, title, text):
    try:
        import tkinter as tk
        from tkinter import messagebox
    except ModuleNotFoundError:
        show_missing_tkinter_message()
        return

    root = tk.Tk()
    root.withdraw()
    if kind == 'error':
        messagebox.showerror(title, text, parent=root)
    else:
        messagebox.showinfo(title, text, parent=root)
    root.destroy()


def run_gui():
    try:
        vpn_link = ask_link_gui()
    except Exception as exc:
        print(f'Ошибка окна: {exc}', file=sys.stderr)
        return 1

    if vpn_link is None:
        return 0

    try:
        output_path = save_config(vpn_link)
    except Exception as exc:
        show_gui_message('error', APP_TITLE, str(exc))
        return 1

    show_gui_message('info', APP_TITLE, f'Конфиг сохранен:\n{output_path}')
    return 0


def run_console(args):
    if args.encode_file:
        output_path = save_vpn_link_from_config(args.encode_file)
        print(f'Ссылка сохранена: {output_path}')
        return 0

    vpn_link = args.link
    if not vpn_link:
        vpn_link = input('Вставьте ссылку vpn://: ').strip()

    output_path = save_config(vpn_link)
    print(f'Конфиг сохранен: {output_path}')
    return 0


def main():
    parser = argparse.ArgumentParser(description='Простой декодер ссылок AmneziaWG vpn://.')
    parser.add_argument('--link', help='Декодировать эту vpn:// ссылку без открытия окна.')
    parser.add_argument('--encode-file', help='Создать vpn:// ссылку из указанного .conf файла.')
    parser.add_argument('--console', action='store_true', help='Использовать консоль вместо окна.')
    args = parser.parse_args()

    if args.console or args.link or args.encode_file:
        return run_console(args)

    return run_gui()


if __name__ == '__main__':
    raise SystemExit(main())
