# BabyRE writeup
## Description
Chạy thử chương trình, yêu cầu nhập mật khẩu => flag

![Run](./run.jpg)

## Analysis with IDA
Ném vào ida để phân tích chương trình

![Main1](./main1.png)

Từ Pseudocode ta thấy hàm sub_401020 và hàm sub_401050 là hàm printf và scanf. Biến v8, v9, v10, v11 lưu 1 chuỗi ký tự. Key nhập vào lưu ở v12. Vòng for thứ nhất cho thấy key nhập vào gồm 5 số, kiểu char 1 byte. Vòng for thứ 2 sử dụng chuỗi ký tự cipher ở trên cùng key để tính toán gen ra flag.

![Main2](./main2.png)
