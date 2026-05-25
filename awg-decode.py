import sys
import struct
import zlib
import base64
import argparse
import socket
import ipaddress
import re
import json

def qCompress(data, level=-1):
    compressed = zlib.compress(data, level)
    header = struct.pack('>I', len(data))
    return header + compressed

def qUncompress(data):
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

def base64url_encode(data):
    encoded = base64.urlsafe_b64encode(data)
    return encoded.rstrip(b'=')

def base64url_decode(data):
    padding_needed = (4 - len(data) % 4) % 4
    data += b'=' * padding_needed
    return base64.urlsafe_b64decode(data)

def is_ip_address(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def resolve_dns_to_ip(dns_name):
    try:
        ip_address = socket.gethostbyname(dns_name)
        return ip_address
    except socket.gaierror:
        return None

def process_conf_data(data):
    def replace_endpoint(match):
        full_line = match.group(0)
        prefix = match.group(1)
        address = match.group(2)
        port = match.group(3)
        suffix = match.group(4)
        if not is_ip_address(address):
            resolved_ip = resolve_dns_to_ip(address)
            if resolved_ip:
                print(f"Resolved DNS '{address}' to IP '{resolved_ip}'", file=sys.stderr)
                return f"{prefix}{resolved_ip}:{port}{suffix}"
            else:
                print(f"Error: Could not resolve DNS name '{address}'", file=sys.stderr)
                sys.exit(1)
        else:
            return full_line
    pattern = r'^(.*Endpoint\s*=\s*)([^\s:]+)(?::(\d+))(.*)$'
    return re.sub(pattern, replace_endpoint, data, flags=re.MULTILINE)

def encode(data):
    data_bytes = data.encode('utf-8')
    compressed = qCompress(data_bytes, level=8)
    base64_encoded = base64url_encode(compressed)
    s = 'vpn://' + base64_encoded.decode('ascii')
    return s

def decode(s):
    data = s.replace('vpn://', '')
    data_bytes = data.encode('ascii')
    compressed = base64url_decode(data_bytes)
    uncompressed = qUncompress(compressed)
    if uncompressed:
        result = uncompressed
    else:
        result = compressed
    return result.decode('utf-8')

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
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return {}
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

    for key in ('Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5'):
        append_kv(lines, key, cfg.get(key))

    lines.append('')
    lines.append('[Peer]')
    append_kv(lines, 'PublicKey', first_present(cfg.get('server_pub_key'), cfg.get('public_key'), cfg.get('PublicKey')))
    append_kv(lines, 'PresharedKey', first_present(cfg.get('psk_key'), cfg.get('preshared_key'), cfg.get('PresharedKey')))
    append_kv(lines, 'Endpoint', endpoint)
    append_kv(lines, 'AllowedIPs', ', '.join(allowed_ips))
    append_kv(lines, 'PersistentKeepalive', first_present(cfg.get('persistent_keep_alive'), cfg.get('PersistentKeepalive')))

    return '\n'.join(lines).rstrip() + '\n'

def maybe_extract_config(decoded_data):
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

def main():
    parser = argparse.ArgumentParser(description='Encode and decode VPN configuration files to/from vpn:// format.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encode', action='store_true', help='Encode a .conf file to vpn:// format.')
    group.add_argument('-d', '--decode', action='store_true', help='Decode a vpn:// string to configuration data.')
    parser.add_argument('input', help='Input file for encoding or vpn:// string for decoding.')
    parser.add_argument('-o', '--output', help='Output file. If not specified, output will be printed to console.')

    args = parser.parse_args()

    if args.encode:
        try:
            with open(args.input, 'r', encoding='utf-8') as f:
                data = f.read()
        except FileNotFoundError:
            print(f'Error: File {args.input} not found.')
            sys.exit(1)
        except Exception as e:
            print(f'Error reading file {args.input}: {e}')
            sys.exit(1)

        processed_data = process_conf_data(data)

        encoded_string = encode(processed_data)

        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(encoded_string)
                print(f'Encoded vpn:// string written to {args.output}')
            except Exception as e:
                print(f'Error writing to file {args.output}: {e}')
        else:
            print(encoded_string)

    elif args.decode:
        vpn_string = args.input

        decoded_data = maybe_extract_config(decode(vpn_string))

        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(decoded_data)
                print(f'Decoded configuration data written to {args.output}')
            except Exception as e:
                print(f'Error writing to file {args.output}: {e}')
        else:
            print(decoded_data)

if __name__ == '__main__':
    main()
