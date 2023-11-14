## __stack_chk_fail

- khi ta có BOF, có luôn cả win , có mọi thứ ta cần nhưng mà chall lại có canary mà ta ko thể nào leak được, ta phải làm sao đây ??
- và giờ ta sẽ research cách bypass nó

## reference 

https://learn.dreamhack.io/4#1

## summary 
- khi ta làm orw thằng canary thì chall sẽ xuất hiện 1 hàm để check canary là __stack_chk_fail
- ta hoàn toàn có thể orw got __stack_chk_fail thành hàm tạo shell sau khi orw canary
- khi chạy vào hàm __stack_chk_fail ta sẽ có được shell 
