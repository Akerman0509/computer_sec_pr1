**Yêu cầu hệ thống**
- Hệ điều hành: Linux (Ubuntu khuyến nghị) hoặc macOS
- Python: 3.12
- MySQL: 8.0 trở lên
- Redis: 6.0 trở lên

**Các thư viện Python**
- django
- djangorestframework
- mysqlclient
- cryptography
- qrcode
- pyzbar
- redis

**Cấu trúc dự án**
Thư mục chính: computer_sec_pr1
- applications/my_app/: Chứa models, views, utils, và các file liên quan.
- data/logs/: Lưu log (security.log).
- applications/data/EncrypteLargeFile/Encrypted: Lưu tệp mã hóa.
- applications/data/EncrypteLargeFile/Upload: Lưu tệp cần mã hóa.
- applications/data/signatures/: Lưu tệp chữ ký số.
- applications/data/qr_codes/: Lưu mã QR.
- applications/data/upload_qr/: Lưu mã QR tải lên.

**Thiết lập môi trường**
1. Tạo và kích hoạt môi trường ảo:
cd ~/Documents/Project1/computer_sec_pr1
python3 -m venv venv
source venv/bin/activate

2. Cài đặt các thư viện:
pip install django djangorestframework mysqlclient cryptography qrcode pillow pyzbar redis

3. Thiết lập MySQL:
`sudo service mysql start`
*Tạo file .env*
```
DB_NAME=COMPUTER_SEC  
DB_USER=root
DB_PASSWORD=1111
DB_HOST=localhost
DB_PORT=3306
DEBUG=True
```
*Tạo cơ sở dữ  liệu:*
```
sudo mysql -u root -p
CREATE DATABASE computer_sec_pr1;
EXIT;
```
*Chạy Migrations:*
```
python manage.py makemigrations
python manage.py migrate
```
4. Tạo thư mục:
```
mkdir -p data/logs
mkdir applications/data/EncrypteLargeFile/Encrypted
mkdir applications/data/EncrypteLargeFile/Upload
mkdir applications/data/signatures
mkdir applications/data/qr_codes
mkdir applications/data/upload_qr
chmod -R 777 applications/data/EncrypteLargeFile/Encrypted
chmod -R 777 applications/data/EncrypteLargeFile/Upload
chmod -R 777 applications/data/signatures
chmod -R 777 applications/data/qr_codes
chmod -R 777 applications/data/upload_qr
```
**Chạy server**
```
python manage.py runserver
```


