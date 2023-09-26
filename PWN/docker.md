```
sudo docker build . -t <tendocker> # build docker
sudo docker images # xem docker đã build được chưa
sudo docker run --rm -p<PORT>:<PORT> -it <tendocker> # chạy docker
nc 0 PORT # kết nối
ps aux | grep <namechall> # tìm pid
gdb -p <pid> # debug
sudo docker ps # qua tab khác, tìm CONTAINER ID
sudo docker cp <CONTAINER ID>:<path/libc> . # tải libc
sudo docker cp <CONTAINER ID>:<path/ld> .  # tải ld
```
