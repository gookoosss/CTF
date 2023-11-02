# Stack Pivoting 

- Stack Pivoting là 1 kỹ thuật giúp ta xử lý các tình huống khi không đủ bộ nhớ stack để ghi dữ liệu, lúc này ta sẽ ko thể set up được các syscall hoặc shellcode
- thông thường các hàm khi kết thúc với leave ; ret gadget, vậy ta cần hiểu leave có dạng như thế này: 

```c 
mov rsp, rbp
pop rbp
```
- để dễ hình dung hơn thì xem ví dụ này: 

![image](https://github.com/gookoosss/CTF/assets/128712571/edb66096-3392-4e79-9e25-5c588006c054)



- nếu bạn để ý thì mỗi khi ta overwrite rip , đồng nghĩa ta cũng đã overwrite rbp, với việc kết thúc bằng leave;ret gadget, ta có thể kiểm soát thanh ghi RSP và làm giả nó thành 1 địa chỉ ghi được, lúc này dữ liệu ta nhập vào sẽ được đặt vào địa chỉ giả này , và dĩ nhiên nó là rất lớn và vô tận
- đây là một kĩ thuật khá dễ và đơn giản nhưng lại rất hiểu quả cho các chall khó, nên các bạn có thể tham khảo thêm tài liệu bên dưới để hiểu rõ hơn 

## Reference

https://ir0nstone.gitbook.io/notes/types/stack/stack-pivoting/exploitation/pop-rsp
