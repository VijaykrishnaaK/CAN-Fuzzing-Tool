#include <stdint.h>

extern uint32_t _estack;
extern uint32_t _sdata, _edata, _etext;
extern uint32_t _sbss,  _ebss;
extern int main(void);

void Default_Handler(void) { while(1); }
void Reset_Handler(void);

__attribute__((section(".isr_vector"), used))
uint32_t vector_table[] = {
    (uint32_t)&_estack,
    (uint32_t)&Reset_Handler,
    (uint32_t)&Default_Handler,
    (uint32_t)&Default_Handler,
    (uint32_t)&Default_Handler,
    (uint32_t)&Default_Handler,
    (uint32_t)&Default_Handler,
    0, 0, 0, 0,
    (uint32_t)&Default_Handler,
    (uint32_t)&Default_Handler,
    0,
    (uint32_t)&Default_Handler,
    (uint32_t)&Default_Handler,
};

void Reset_Handler(void) {
    uint32_t *src = &_etext;
    uint32_t *dst = &_sdata;
    while (dst < &_edata) *dst++ = *src++;
    dst = &_sbss;
    while (dst < &_ebss) *dst++ = 0;
    main();
    while(1);
}
