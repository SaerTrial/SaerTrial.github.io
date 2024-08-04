---
title: SCTF 2020 Password Lock Plus - Solved by Several Approaches
categories:
- emulation
- firmware reversing
- hardware
- ctf
---

You could find more inforamtion about this challenge in this [link](https://ctftime.org/task/12253). I am going to propose three different approaches to solve this challenge, and those approaches range from hardware to emulation, instead of just static analysis.


## About this challenge

This is a password locker firmware built upon stm32f103c8t6, which is sort of ubiquitous in today's iot hacking tutorials ;) 

Four GPIO channels (GPIO_PA1, GPIO_PA2, GPIO_PA3, GPIO_PA4) are provided for users to type in passwords, which are representing number 1 to 4:
1. the format of flag1 is SCTF{passowrd}
2. once a correct password is provided, the firmware sends flag2 via UART-TX at PA9

Tips: interrupt vector table, datasheet, jtag allowed, dynamically debuggable, trigger mode on pushing botton.


## Firmware reversing

According to cortex-m convention, there are stack address and the reset handler at the first eight bytes. Following through reset handler, we finally identify main function inhabiting at 0x08000428. Beware that 0x8000000 is base address for code section. Another intuition to support this identification is a super loop within this function. Overall, the analyzed ghidra zip file is [here]({{ site.baseurl }}/assets/binary/2024-08-04-sctf-password-locker/password-locker.gzf).

### SVD

In order to better understand how peripherals are setup in the firmeware logic, we use svd-loder in ghidra scripts to automatically create MMIO ranges for all peripherals. Download a svd file of this MCU at the [link](https://github.com/fduignan/stm32f103c8t6/blob/master/STM32F103.svd). Search the script `svd-loder`. Once this script had been executed, it is fairly easy to identify `Uart_Send`. Moreover, the firmware sends `SCTF{` before diving into an infinite loop.

```c

void main(void)

{
  undefined *puVar1;
  undefined *peripheral;
  
  FUN_080002f0();
  peripheral = PTR_RCC_08000594;
  *(undefined4 *)(PTR_RCC_08000594 + 0x18) = 0;
  *(uint *)(peripheral + 0x18) = *(uint *)(peripheral + 0x18) | 1;
  puVar1 = PTR_RCC_08000594;
  *(uint *)(PTR_RCC_08000594 + 0x18) = *(uint *)(peripheral + 0x18) | 0x4004;
  *(undefined4 *)(puVar1 + 0x14) = 1;
  peripheral = PTR_GPIOA_0800059c;
  *(dword *)PTR_GPIOA_0800059c = DWORD_08000598;
  *(undefined4 *)(peripheral + 4) = 444444B4;
  *(undefined4 *)(PTR_GPIOA_0800059c + 0xc) = 0b00011110;
  *(undefined4 *)PTR_EXTI_080005a4 = 0b00011110;
                    /* falling trigger enabled */
  *(undefined4 *)(PTR_EXTI_080005a4 + 0xc) = 0b00011110;
  peripheral = PTR_AFIO_080005a8;
  *(undefined4 *)(PTR_AFIO_080005a8 + 0xc) = 0;
  *(undefined4 *)(peripheral + 0x10) = 0;
  FUN_080003b0(7);
  FUN_080003b0(8);
  FUN_080003b0(9);
  FUN_080003b0(10);
  peripheral = PTR_RCC_08000594;
  *(uint *)(PTR_RCC_08000594 + 0xc) = *(uint *)(PTR_RCC_08000594 + 0xc) | 0x4000;
  *(uint *)(peripheral + 0xc) = *(uint *)(peripheral + 0xc) & 0xffffbfff;
  peripheral = PTR_USART1.BRR_080005ac;
  *(undefined2 *)PTR_USART1.BRR_080005ac = 0x271;
  *(undefined2 *)(peripheral + 4) = 0x2008;
  UART_Send(L'S');
  UART_Send(L'C');
  UART_Send(L'T');
  UART_Send(L'F');
  UART_Send(L'{');
  *(undefined2 *)(PTR_USART1.BRR_080005ac + 0xc) = 0x80;
  peripheral = 40020000_DMA;
  *(undefined4 *)(40020000_DMA + 0x50) = 0x20000000;
  *(undefined **)(peripheral + 0x4c) = PTR_USART1.BRR_080005ac + -4;
  *(undefined4 *)(peripheral + 0x48) = 0x1e;
  *(undefined4 *)(peripheral + 0x44) = 0x492;
  FUN_080003b0(0xe);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}

```

### Peripheral configuration

A few question arise. How is GPIO port A configured and used? What about DMA? [Datasheet](https://www.st.com/resource/en/reference_manual/rm0008-stm32f101xx-stm32f102xx-stm32f103xx-stm32f105xx-and-stm32f107xx-advanced-armbased-32bit-mcus-stmicroelectronics.pdf) details everything we need.

Let us research into operation mode first:
```c
*(dword *)GPIOA_40010800 = DWORD_08000598 //44488884h;
```

According to datasheet, this address sets up output data registers to activate some of pins in output mode. This case configures PA1 to PA4. 

```c
*(undefined4 *)PTR_EXTI_080005a4 = 0b00011110;
```
This enables external interrupts for four pins mentioned above, which means that the program will jump to a corresponding routine once any of those bottons is pushed.

The interrupt vector table indicates where they are:
```
        0800005c 6d 01 00 08     addr       EXIT1+1
        08000060 ad 01 00 08     addr       EXIT2+1
        08000064 e5 01 00 08     addr       EXIT3+1
        08000068 2d 02 00 08     addr       EXIT4+1
```


```c
*(undefined4 *)(PTR_EXTI_080005a4 + 0xc) = 0b00011110;
```
This setup is really crucial since it specifies falling trigger mode to be enabled. This means that we need to create a falling edge to trigger those interrupts.

![Image alt]({{ site.baseurl }}/assets/pic/2024-08-04-sctf-password-locker/falling-trigger-mode.png"falling trigger mode").


Those interrupt handlers will check if a user pushes bottons in a correct order. If so, flag2 will be sent to UART-TX via DMA. For example, `EXIT2` does data transmission by enabling DMA.
```c
void EXIT3(void)
{
  *DAT_0800021c = 8;
  if (*2000003C == '\x06') {
    *(undefined *)(20000000 + 0xc) = '_';
    // enable DMA
    *(uint *)(40020000 + 0x44) = *(uint *)(40020000 + 0x44) | 1;
    *2000003C = *2000003C + '\x01';
  }
  ...
}
```


```c
  peripheral = 40020000_DMA;
  *(undefined4 *)(40020000_DMA + 0x50) = 0x20000000;
  *(undefined **)(peripheral + 0x4c) = PTR_USART1.BRR_080005ac + -4;
  *(undefined4 *)(peripheral + 0x48) = 0x1e;
  *(undefined4 *)(peripheral + 0x44) = 0x492;
```

Here is crucial as well, because we directly figure out a source or destination address over entire DMA data transmission. 



## First approach - static analysis

Throughout the previous analysis, we roughly know how to acquire its password by checking four external interrupt handlers. So, it is way easy to get the first flag ;(

Furthermore, password has been presented already in the `main`:
```c
DAT_080005a4[4] = DAT_080005a4[4] | 2;
delay(1);
DAT_080005a4[4] = DAT_080005a4[4] | 0x10;
delay(1);
DAT_080005a4[4] = DAT_080005a4[4] | 0x10;
delay(1);
DAT_080005a4[4] = DAT_080005a4[4] | 4;
delay(1);
DAT_080005a4[4] = DAT_080005a4[4] | 0x10;
delay(1);
DAT_080005a4[4] = DAT_080005a4[4] | 2;
delay(1);
DAT_080005a4[4] = DAT_080005a4[4] | 8;
delay(1);
```
Hence, we could naturally listen on PA9 for the second flag after the device finishes reboot. This is damn boring~~

So, I patched those silly code snippets that sort of leak password in order to have more fun ;)

The other two approaches are propsed upon the [patch version]({{ site.baseurl }}/assets/binary/2024-08-04-sctf-password-locker/patched_firmware.bin).




## Second approach - hardware fuzzing

We already know passwords consist of six digits. Each digit could only be between 1 and 4. I do know firmware is not easily accessible or acquirable in most cases. For example, a firmware binary is stored in NOR flash or NAND flash, which makes it a bit harder to dump the firmware binary.

When it comes to this challenge, I leverage hydrabus to write down a script to automatically perform fuzz testing of this device. Beforehand, I have already burned this patched firmware in my blue pill board, which uses the exactly same MCU as this challenge does.

For convenience (I am too lazy or mentally tired to type so many words), I directly demonstrate my hydrabus script:
```python
```


Once the hydrabus connects its four pins to PA1-4 in the blue pill, I run this script to generate 