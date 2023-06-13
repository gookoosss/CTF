# PWN2 - cách 2

cách này khá hay và lạ từ bạn **@hlaan** đã chỉ mình 

**tại cách này ta sẽ xem kĩ ida để khai thác:**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/b43ef90b-8b53-4362-8c41-0d68563fa55d)


ta để ý lần nhập 1 , tại đây ko có lỗi BOF nhưng giá trị nhập vào **input** , ấn vào **input** thì ta thấy **input** là **1 địa chỉ tĩnh** có thể khai thác dễ dàng được

![image](https://github.com/gookoosss/CTF.-/assets/128712571/92cb11bf-c49e-416f-8dc1-0b8d65a50756)


**debug xem sao :** 

![image](https://github.com/gookoosss/CTF.-/assets/128712571/908bfd9a-93be-404f-98b3-275448bde325)


tại đây ta thấy dữ liệu nhập vào **input** tại 1 địa chỉ tĩnh cố định là **0x00000000404090**, từ đó ta có thể khai thác để gán **/bin/sh\0** vào, lúc này **0x00000000404090** sẽ chứa **/bin/sh** và ta sẽ gán vào **rdi bằng pop rdi** 

**(có note lại trong ảnh)**

![image](https://github.com/gookoosss/CTF.-/assets/128712571/4567dcba-ef23-4e57-8ccf-23f9d8980721)


h mình kiểm tra xem dữ liệu trỏ về đúng ko

![image](https://github.com/gookoosss/CTF.-/assets/128712571/e2072099-1a5b-4351-8120-e3b7db956c12)


oke đúng rồi đó

**flag:**

**n00bz{3xpl01tw1th0u7w1n5uc355ful!}**
