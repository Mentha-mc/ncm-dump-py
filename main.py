import binascii,struct,base64,json,os,sys
from Crypto.Cipher import AES
def decrypt_ncm(file_path):
    core_key = binascii.a2b_hex("687A4852416D736F356B496E62617857")
    meta_key = binascii.a2b_hex("2331346C6A6B5F215C5D2630553C2728")
    unpad = lambda s: s[0:-(s[-1] if type(s[-1]) == int else ord(s[-1]))]
    with open(file_path, 'rb') as f:
        header = f.read(8)
        assert binascii.b2a_hex(header) == b'4354454e4644414d', "不是有效的NCM文件"
        f.seek(2, 1)
        key_length = struct.unpack('<I', f.read(4))[0]
        key_data = bytearray(f.read(key_length))
        for i in range(len(key_data)):
            key_data[i] ^= 0x64
        cryptor = AES.new(core_key, AES.MODE_ECB)
        key_data = unpad(cryptor.decrypt(bytes(key_data)))[17:]
        key_box = build_key_box(key_data)
        meta_length = struct.unpack('<I', f.read(4))[0]
        meta_data = bytearray(f.read(meta_length))
        for i in range(len(meta_data)):
            meta_data[i] ^= 0x63
        meta_data = base64.b64decode(bytes(meta_data)[22:])
        cryptor = AES.new(meta_key, AES.MODE_ECB)
        meta_data = unpad(cryptor.decrypt(meta_data)).decode('utf-8')[6:]
        meta_data = json.loads(meta_data)
        crc32 = struct.unpack('<I', f.read(4))[0]
        f.seek(5, 1)
        image_size = struct.unpack('<I', f.read(4))[0]
        image_data = f.read(image_size)
        file_name = os.path.basename(file_path).split(".ncm")[0] + '.' + meta_data['format']
        output_path = os.path.join(os.path.dirname(file_path), file_name)
        with open(output_path, 'wb') as m:
            while True:
                chunk = bytearray(f.read(0x8000))
                if not chunk:
                    break
                for i in range(len(chunk)):
                    j = (i + 1) & 0xff
                    chunk[i] ^= key_box[(key_box[j] + key_box[(key_box[j] + j) & 0xff]) & 0xff]
                m.write(chunk)
    return file_name
def build_key_box(key_data):
    key_box = bytearray(range(256))
    key_length = len(key_data)
    c = 0
    last_byte = 0
    key_offset = 0    
    for i in range(256):
        swap = key_box[i]
        c = (swap + last_byte + key_data[key_offset]) & 0xff
        key_offset += 1
        if key_offset >= key_length:
            key_offset = 0
        key_box[i] = key_box[c]
        key_box[c] = swap
        last_byte = c
    return key_box
if __name__ == '__main__':
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
        print(f"正在处理文件: {filepath}")
        try:
            output_file = decrypt_ncm(filepath)
            print(f"转换成功! 输出文件: {output_file}")
        except Exception as e:
            print(f"转换失败: {str(e)}")
    else:
        filepath = r"C:\code\ncmdump\xxx.ncm"
        print(f"正在处理文件: {filepath}")
        try:
            output_file = decrypt_ncm(filepath)
            print(f"转换成功! 输出文件: {output_file}")
        except Exception as e:
            print(f"转换失败: {str(e)}")