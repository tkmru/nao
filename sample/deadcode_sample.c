#include <stdio.h>

int main(void) {
  __asm__ __volatile__(
    "mov $0x1918632, %eax\n\t"
    "shr $0x10, %eax\n\t"
    "add $0x913, %eax\n\t"
    "and $0x1fff, %eax\n\t"
    "mov %eax, %ecx\n\t"
    "mov $0x10000, %ecx\n\t"
    "mov $0x1918632, %eax\n\t"
    "and $0x600, %ecx\n\t"
    "mov $0x800, %ecx\n\t"
  );

  printf("deadcode sample bin.\n");

  return 0;
}
