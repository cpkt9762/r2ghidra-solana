#include "sol/return_data.h"
#include <solana_sdk.h>

extern uint64_t entrypoint(const uint8_t *input) {
  uint64_t stack_height = *(const uint64_t *)(input + 16);
  sol_log("this is c test");
  sol_set_return_data((const uint8_t *)&stack_height, sizeof(stack_height));
  return stack_height;
}
