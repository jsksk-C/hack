#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 简单的安全字符串拷贝示例（C）
 展示要点：
 - 始终传入目标缓冲区长度并保证以 '\0' 结尾
 - 检查输入长度以避免截断导致的逻辑错误
 - 在处理完敏感数据后显式清零，防止被内存残留
*/

/* 安全拷贝：确保目标字符串以 '\0' 结尾，返回 0 表示成功，非0 表示截断或错误 */
int safe_str_copy(char *dst, size_t dst_size, const char *src) {
    if (dst == NULL || src == NULL || dst_size == 0) return -1;

    size_t src_len = strlen(src);
    if (src_len >= dst_size) {
        /* 拷贝可容纳的前 dst_size-1 字节，强制以 '\0' 结尾 */
        memcpy(dst, src, dst_size - 1);
        dst[dst_size - 1] = '\0';
        return 1; /* 表示发生截断 */
    }

    memcpy(dst, src, src_len + 1);
    return 0; /* 成功 */
}

/* 显式清零：使用 volatile 指针防止编译器优化掉清零操作 */
void secure_clear(void *v, size_t n) {
    volatile unsigned char *p = (volatile unsigned char *)v;
    while (n--) *p++ = 0;
}

int main(void) {
    char input[512]; /* 临时接收（假设来源可信度有限） */
    char secret[64]; /* 目标缓冲区，演示边界检查 */

    printf("请输入一段文本（示例：可能的密码或敏感字符串）：\n");
    if (fgets(input, sizeof(input), stdin) == NULL) {
        fprintf(stderr, "读取输入失败\n");
        return 2;
    }
    /* 去除尾部换行 */
    size_t len = strlen(input);
    if (len > 0 && input[len-1] == '\n') input[len-1] = '\0';

    int rc = safe_str_copy(secret, sizeof(secret), input);
    if (rc == 1) {
        printf("警告：输入被截断以适配目标缓冲区（%zu 字节）\n", sizeof(secret));
    }

    printf("拷贝后的内容（最多 %zu 字节）: %s\n", sizeof(secret)-1, secret);

    /* 假装对 secret 做了敏感操作（例如验证密码），然后清零 */
    printf("现在将对敏感数据执行清零操作...\n");
    secure_clear(secret, sizeof(secret));

    /* 为演示，显示已清零后的内容（注意：真实程序不要打印敏感数据） */
    printf("清零后 secret 前几个字节（十六进制）: ");
    for (size_t i = 0; i < 8 && i < sizeof(secret); ++i) printf("%02x ", (unsigned char)secret[i]);
    printf("\n程序结束。\n");
    
    /* 也清零 input（如果它也包含敏感数据） */
    secure_clear(input, sizeof(input));

    return 0;
}
