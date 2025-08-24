#include <category/ffi/cxx_env.h>

void monad_cxx_env_init_quill(void (*callback)(struct QuillLogEvent const *))
{
    println(stderr, "called init_quill");
}
