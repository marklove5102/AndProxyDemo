//
// Created by lenovo on 2026/3/14.
//

#ifndef LOG_H
#define LOG_H

#include <android/log.h>

#define TAG "BinderProxy"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)

#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static inline void dump(const void *ptr, size_t size) {
    if (ptr == nullptr || size == 0) {
        LOGD("dump: NULL pointer or zero size");
        return;
    }

    const auto *data = (const unsigned char *)ptr;
    size_t offset = 0;

    while (offset < size) {
        char hex[64] = {0};      // 存储十六进制字符串
        char ascii[17] = {0};    // 存储 ASCII 表示
        int i, pos = 0;

        for (i = 0; i < 16 && offset + i < size; i++) {
            unsigned char c = data[offset + i];
            // 十六进制部分，每字节两个十六进制数字加一个空格
            pos += sprintf(hex + pos, "%02x ", c);
            // 每 8 字节后添加一个额外空格，使分组更清晰
            if (i == 7) {
                pos += sprintf(hex + pos, " ");
            }
            // ASCII 部分，可打印字符保留，不可打印显示为 '.'
            ascii[i] = (c >= 0x20 && c <= 0x7E) ? c : '.';
        }

        // 如果最后一行不足 16 字节，用空格补齐十六进制显示
        for (; i < 16; i++) {
            pos += sprintf(hex + pos, "   ");
            if (i == 7) {
                pos += sprintf(hex + pos, " ");
            }
            ascii[i] = ' ';
        }
        ascii[16] = '\0';

        // 输出一行，偏移量固定为 8 位十六进制
        LOGD("%08zx:  %s %s", offset, hex, ascii);
        offset += 16;
    }
}

#endif //LOG_H
