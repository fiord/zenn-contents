---
title: "ångstromCTF 2021 - Float On"
emoji: "🤖"
type: "tech" # tech: 技術記事 / idea: アイデア
topics: ["CTF", "Misc", "Easy"]
published: true
---

### 問題概要

> I cast my int into a double the other day, well nothing crashed, sometimes life's okay.
> 
> We'll all float on, anyway: [float_on.c](https://files.actf.co/1db38765cff4dc6d4f049cf65f24a91f09162f919c6c6bdc4506a32c4f65c767/float_on.c).
> 
> Float on over to `/problems/2021/float_on` on the shell server, or connect with `nc shell.actf.co 21399`.

```c:float_on.c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#define DO_STAGE(num, cond) do {\
    printf("Stage " #num ": ");\
    scanf("%lu", &converter.uint);\
    x = converter.dbl;\
    if(cond) {\
        puts("Stage " #num " passed!");\
    } else {\
        puts("Stage " #num " failed!");\
        return num;\
    }\
} while(0);

void print_flag() {
    FILE* flagfile = fopen("flag.txt", "r");
    if (flagfile == NULL) {
        puts("Couldn't find a flag file.");
        return;
    }
    char flag[128];
    fgets(flag, 128, flagfile);
    flag[strcspn(flag, "\n")] = '\x00';
    puts(flag);
}

union cast {
    uint64_t uint;
    double dbl;
};

int main(void) {
    union cast converter;
    double x;

    DO_STAGE(1, x == -x);
    DO_STAGE(2, x != x);
    DO_STAGE(3, x + 1 == x && x * 2 == x);
    DO_STAGE(4, x + 1 == x && x * 2 != x);
    DO_STAGE(5, (1 + x) - 1 != 1 + (x - 1));

    print_flag();

    return 0;
}
```

### 解説
`x`を`uint64`で与えて、それを`double`型で解釈したときに`DO_STAGE`で与えられている式を満たすようにする問題です。

Cにおける`double`の処理は[IEEE 754](https://ja.wikipedia.org/wiki/IEEE_754#64%E3%83%93%E3%83%83%E3%83%88%E5%80%8D%E7%B2%BE%E5%BA%A6%E3%81%AE%E4%BA%A4%E6%8F%9B%E5%BD%A2%E5%BC%8F)で規定されていて、これを見ながらそれぞれの条件に合う数字を探していくことになります。

1. `x == -x`: これを満たす代表例として$0$を考えるのは自然でしょう。
2. `x != x`: これは`NaN`が満たします。
3. `x + 1 == x && x * 2 == x`: これは`infinity`が満たします。
4. `x + 1 == x && x * 2 != x`: これは非常に大きい数（具体的に$1$を足しても数が変わらないよう、仮数部でカバー出来ない程に大きければOKです。有効数字は大体15桁とかなので、多分$10$進数における$20$桁以上の数字なら大丈夫でしょう。僕は$100$桁でやりました。
5. `(1 + x) - 1 != 1 + (x - 1)`: これは少し悩んだのですが、`NaN`はこれを満たします。`NaN`に関するルールで以下があるためです。
    - `NaN`と数字の演算は`NaN`になる。この結果、右辺と左辺はそれぞれ`NaN`になる
    - `NaN == NaN`は`false`

この結果からそれぞれ与えるべき`double`としての`x`は求まったので、これを`uint64`型に変換して与える必要があります。まぁ問題で与えられている手法の逆で変換すれば出来るので...

```c:convert.c
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <assert.h>

union cast {
  uint64_t uint;
  double dbl;
};

int main() {
  union cast conv;

  // stage 1: x == -x, x = 0
  conv.dbl = 0.0;
  printf("%lu\n", conv.uint);
  // stage 2: x != x, x = NaN
  conv.dbl = NAN;
  printf("%lu\n", conv.uint);
  // stage 3: x + 1 == x, x * 2 == x, x is infinity
  conv.dbl = INFINITY;
  printf("%lu\n", conv.uint);
  // stage 4: x + 1 == x, x * 2 != x, x is very huge number
  conv.dbl = 1e100;
  printf("%lu\n", conv.uint);
  // stage 5: (1 + x) - 1 != 1 + (x - 1), x is NaN
  conv.dbl = NAN;
  double x = conv.dbl;
  if ((1 + x) - 1 != 1 + (x - 1)) {
    printf("%lu\n", conv.uint);
  } else {
    printf("stage 5 failed\n");
  }

  return 0;
}
```

```python:solve.py
from pwn import *
context.log_level = "debug"

r = remote("shell.actf.co", 21399)

r.recvuntil(b"Stage 1: ")
r.sendline("0")
r.recvuntil(b"Stage 2: ")
r.sendline("9221120237041090560")
r.recvuntil(b"Stage 3: ")
r.sendline("9218868437227405312")
r.recvuntil(b"Stage 4: ")
r.sendline("6103021453049119613")
r.recvuntil(b"Stage 5: ")
r.sendline("9221120237041090560")

r.interactive()
```