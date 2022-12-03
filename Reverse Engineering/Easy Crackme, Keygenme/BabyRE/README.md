# BabyRE writeup
## Description
Chạy thử chương trình, yêu cầu nhập mật khẩu => flag

![Run](./run.jpg)

## Analysis with IDA
Ném vào ida để phân tích chương trình

![Run](./main1.jpg)

Từ Psuedo code, ta nhận thấy hàm sub_401020 và sub_401050 là hàm printf và scanf. Biến v8, v9, v10, v11 lưu 1 chuỗi ký tự. Key sau khi nhập vào lưu ở v12. Vòng lặp for thứ nhất cho thấy key nhập vào gồm 5 số, kiểu char 1 byte. Vòng for thứ 2 để tính toán gen ra flag.

![Run](./main2.jpg)
