# implementation of schnorr, BN(Bellare-Neven) & MuSig based on 
# Jimmy Song's presentation (https://prezi.com/amezx3cubxy0/schnorr-signatures/)
# Also checks his youtube on this - https://www.youtube.com/watch?v=thfCtc4jJZo (What is Schnorr, BN, Musig?)

# using the codebase which is used in Programming Blockchain seminar(http://programmingblockchain.com/) 
# The codebase can be found in (https://github.com/jimmysong/pb-exercises)

# additional pointer for MuSig
# Key Aggregation for Schnoor Signatures(https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures.html)

import pickle
import ecc
from ecc import PrivateKey, S256Field, S256Point
from random import randint
from helper import double_sha256, little_endian_to_int
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
import os
from hashlib import sha256
# hash
def H(*args):
    '''
    Băm 2 lần sử dụng hàm băm sha256
    '''
    return double_sha256(b''.join(args))

# int(hash)
def HI(*args):
    '''
    Chuyển đổi kiểu byte sang kiểu int
    '''
    return little_endian_to_int(H(*args))


def verify(V, s, z, A):
    '''
    Xác thực bản tin z dựa vào thông tin xác thực (là V và s)
    và khóa công khai (A)
    '''
    # print(V, s, A)
    Q = s * ecc.G - HI(V.sec(),z) * A
    return Q == V

def create_key():
    '''
    Tạo khoá bí mật và khoá công khai
    Khoá bí mật để ký bản tin,
    khoá công khai để xác thực bản tin (đã được ký)
    Bất kỳ ai cũng có thể xác thực dựa vào khoá công khai kèm theo giá trị xác thực (R, s)
    Sau khi tạo xong khoá, khoá được lưu vào tệp Private.key để sử dụng sau này (chủ yếu để ký)
    '''
    if not os.path.isdir('Keys'):
        if os.path.isfile('Keys'):
            os.remove('Keys')
        os.mkdir('Keys')
    pk = PrivateKey(randint(0, 2**256)) # tạo khóa công khai và khóa bí mật (A, a theo RFC A = point, a = secret)
    
    with open(os.path.join('Keys','Private.key'), 'wb') as f:
        pickle.dump(pk, f)
    
    return 1

def sign_docs(filename:str):
    '''
    filename: tên file (đường dẫn đến file, có thể là đường dẫn tuyệt đối đến file)

    Hàm có chức năng ký lên tệp filename, tạo ra tệp mới có tên filename_signed
    '''
    # if not os.path.isdir('Signed Files'):
    #     if os.path.isfile('Signed File'):
    #         os.remove('Signed Files')
    #     os.mkdir('Signed Files')
    if not os.path.isfile(os.path.join('Keys','Private.key')):
        return -1
    try:
        with open(os.path.join('Keys','Private.key'), 'rb') as f: # mở file chứa khoá và đọc khoá
            pk = pickle.load(f)
        A = pk.point #lấy khoá công khai
    except Exception as expt:
        print(expt)
        return -2
    # print(point.get_data_as_str())

    v = randint(0, 2**256)
    V = v * ecc.G

    with open(filename, 'rb') as file_sign: # mở file để ký
        data = file_sign.read()
        s = (v + HI(V.sec(), data) * pk.secret)%ecc.N
        data_pad = pad(data, AES.block_size) #đệm file 
        end_byte = pad(((V.get_data_as_str() + '|' + str(s))+ '|' 
                + A.get_data_as_str()).encode('utf8'), AES.block_size) #đóng gói + đệm chữ ký và khoá công khai
        # print(len(end_byte))
        new_data = data_pad + end_byte
        with open(filename+'_signed', 'wb') as signed_file: # ghi nội dung file và chữ ký + khoá công khai (sau khi đệm) 
            signed_file.write(new_data)                     #vào file mới có tên là tên cũ + signed


    return 0

def verify_docs(filename:str):
    '''
    Xác thực file đã được ký hay chưa
    Đầu vào: tên file đã được ký, nếu chưa được ký -> định dạng file sai, hàm trả về False
    Nếu file đúng định dạng (đã được ký):
    nếu chữ ký hợp lệ với nội dung file -> trả về True
    Nếu chữ ký không hợp lệ với nội dung file -> trả về False
    '''
    try:
        # print(filename)
        with open(filename, 'rb') as f:
            data = f.read()
            end_bytes = data[-704:] # 400 byte cuối cùng của file là chữ ký + khoá công khai (đã được đệm)
            file_pad = data[:-704] # còn lại là nội dung file (đã được đệm)
            end_bytes = unpad(end_bytes, AES.block_size) # bỏ đệm chữ ký và khoá công khai
            file_unpad = unpad(file_pad, AES.block_size) # bỏ đệm nội dung file

            [x, y, a, b, s, px, py, pa, pb] = end_bytes.decode('utf8').split('|') # từ lấy chữ ký, khoá công khai
            # print(s)
            # Để khởi tạo lại khóa công khai và V (theo RFC) cần các giá trị x, y, a, b (của V) 
            # và px, py, pa, pb (của A) để khởi tạo lại giá trị của V và A
            V = S256Point(S256Field(int(x)), S256Field(int(y)), S256Field(int(a)), S256Field(int(b))) 
            # print(V)
            A = S256Point(S256Field(int(px)), S256Field(int(py)), S256Field(int(pa)), S256Field(int(pb))) #  
            return verify(V, int(s), file_unpad, A)
    except Exception:
        return False
# create_key() #Tạo khoá
# sign_docs('README.md') # ký nội dung file Readmy.md
# print(verify_docs('README.md_signed')) # xác thực nội dung file e.md_signed
