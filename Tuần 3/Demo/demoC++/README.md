\# RSA Digital Signature Demo



Ứng dụng mô phỏng chữ ký số RSA bằng C++ Win32 API và OpenSSL.



\## Chức năng



\- Tạo khóa RSA tự động

\- Tạo khóa RSA thủ công

\- Ký văn bản

\- Kiểm tra chữ ký

\- Lưu chữ ký ra file

\- Giả mạo chữ ký



\## Công nghệ sử dụng



\- C++

\- Win32 API

\- OpenSSL



\## Build



```cmd

cl /EHsc /W3 RSA\_CPP.cpp /I"C:\\OpenSSL-Win64\\include" ^

/link /LIBPATH:"C:\\OpenSSL-Win64\\lib\\VC\\x64\\MT" ^

libssl.lib libcrypto.lib Ws2\_32.lib Crypt32.lib user32.lib ^

comdlg32.lib gdi32.lib comctl32.lib /SUBSYSTEM:WINDOWS

```



\## Tác giả



Nam

