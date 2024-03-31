# Socket C++
## Mô tả dự án
1. Xây dựng chương trình tương tác giữa máy gửi (Client) và máy nhận để xử lí các yêu
cầu (Server) sử dụng giao thức TCP. Giao diện được thực hiện thông qua giao diện dòng
lệnh (Command line tool)
2. Đảm bảo thực hiện được các yêu cầu
– Thiết lập kết nối (senddata, receivedata)
– Gửi text (sendtext)
– Gửi file (sendfile)
3. Một số tính năng nâng cao:
– Khả năng gửi text kèm Unicode và Emotion
– Thực hiện thao tác khác trong quá trình gửi file
– Server cho phép nhiều kết nối/ yêu cầu, khả năng xử lí dữ liệu đảm bảo tính bảo
mật, an toàn và toàn vẹn dữ liệu.
4. Người sử dụng thực hiện gửi các request thông qua giao diện terminal của Client với các
lệnh được quy định trước. Xem rõ hơn ở thư mục Report

## Môi trường phát triển
- Hệ điều hành: Windows
- Ngôn ngữ C++ (C++17 Standard)
- Công cụ: Visual studio

## Một số lệnh được quy định
1. Tọa kết nối:
- senddata \<ip\>:\<port\>
- receivedata -out \<path_to_store\>
2. Send text:  
- sendtext \<text\>   
- *: text có thể chứa khoảng cách, unicode, emotion (dùng windows + .)
3. Send file:
- sendfile \<path\> \<buffer_size\>

## Chạy chương trình
1. Pull source về.
2. Cài thư viện Boost.asi và OpenSSL, chỉnh cửa properties cho project bằng visual studio. Bước này khá phức tạp để cài những thư viện này, cần xem hướng dẫn trên internet để cài thuật lợi hơn.
3. Ctrl + b để build 2 dự án Client hoặc Server. Hoặc F5 để bật terminal cho cả 2 dự án. Chạy Server trước để đảm bảo Client kết nối không lỗi.

## Minh họa
![Connect đến Server](https://github.com/duquochuyy/Socket_Cpp/assets/95600732/d5973551-ba46-4c61-a7e3-c7cdef3d6e4e)
<br/>
Client connect đến Server

![sendtext](https://github.com/duquochuyy/Socket_Cpp/assets/95600732/231ba1e5-d3ea-479e-9235-717a220e86b7)
<br/>
Client thực hiện yêu cầu send text đến Server

![sendfile](https://github.com/duquochuyy/Socket_Cpp/assets/95600732/04c26432-caee-49f7-9b94-76e0fcd9e733)
<br/>
Client thực hiện yêu cầu send file đến Server

![multi client](https://github.com/duquochuyy/Socket_Cpp/assets/95600732/318af5d8-178b-44ee-8e3f-e2b7befa5b24)
<br/>
Nhiều Client cùng kết nối đến Server



