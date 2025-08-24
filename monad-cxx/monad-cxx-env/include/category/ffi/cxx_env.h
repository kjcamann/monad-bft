#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct QuillLogEvent
{
    uint8_t log_level;
};

void monad_cxx_env_init_quill(void (*)(struct QuillLogEvent const *));

#ifdef __cplusplus
} // extern "C"
#endif
