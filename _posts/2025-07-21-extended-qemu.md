---
title:  Extending STM32H7S78-DK in QEMU
categories:
- emulation
---

This post details how to create a custom board in QEMU. Before getting our hands dirty, let me give you some brief introduction about QEMU. QEMU is a very popular tool in system security academia, and a lot of researchers have made custom changes to implement some dedicated functionality, e.g., fuzzing, instrumentation, program analysis, fault injection. 

Moreover, embedded software engineers can benefit from QEMU by creating a prototype board and developing firmware without actually designing a board in the PCB level. However, there are already many building blocks in QEMU and we do not need to build every wheel from scratch, e.g., interrupt controller, CPU. Hence, this post attempts to clarity these steps to ease difficulty in development. In this post, I base QEMU 10.0.2 to implement necessary peripherals to emulate our toy firmware binary built for `STM32H7S78-DK`. This post assocates to [QEMU-STM32H7S78-DK](https://github.com/SaerTrial/QEMU-STM32H7S78-DK). Interesting readers can look into commits to see changes made.

# What board do you want to extend?

As the title mentioned, this post targets at the board "STM32H7S78-DK" and extends it in QEMU. This board is built upon a cortex-m7 MCU with larger flash memory and SRAM. Additionally, this board comes with quite a few complicated peripherals, including Wi‑Fi® module, four user LEDs, etc. Users have to consult its reference manual for more technial details.

# What peripherals have been used in your firmware project?

For simplicity, I created a project with STM32CUBEMX and only implemented UART printing as well as LED blinking. The proceeding code snippet presents all necessary peripherals to be intialized in the `main` function.

```c
int main(void)
{
  /* MCU Configuration--------------------------------------------------------*/

  /* Update SystemCoreClock variable according to RCC registers values. */
  SystemCoreClockUpdate();

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_FLASH_Init();
  MX_UART4_Init();

  // ...
}
```

The primary firmware logic is pretty easy with an `uart_printf` redirecting output to UART4:
```c
#define UART_PRINTF_BUFFER_SIZE 128

void uart_printf(const char *fmt, ...)
{
    char buffer[UART_PRINTF_BUFFER_SIZE];
    va_list args;

    va_start(args, fmt);
    int len = vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    // Ensure output is null-terminated and clipped
    if (len > sizeof(buffer)) len = sizeof(buffer);

    HAL_UART_Transmit(&huart4, (uint8_t *)buffer, len, HAL_MAX_DELAY);
}

int main(void)
{
    while (1)
  {
    /* USER CODE END WHILE */
	int rand_num = rand();
  	if (rand_num % 3 == 0){
        uart_printf("testing branch #0...");
	  }
  	else{
        uart_printf("testing branch #1...\n");
    }

    HAL_Delay(500);	
  }
}
```

# Pick implemented peripherals and components in QEMU code base

Our goal in this post is to emulate the firmware binary and redirect uart output tp a local terminal. According to the previous code snippets and board specification, it is necessary to implement some components, including cortex-m7 mcu, interrupt controller, timer, uart4. Some readers may feel like this is a nightmare and everything needs to be built from zero. In most cases, this would not happen unless most components have not been implemented in QEMU. Furthermore, implementing an interrupt controller takes a lot of considerations to my previous experience.

So, let us sort it out and pick all building blocks already available in QEMU. First, regarding MCU, cortex-m7 respects armv7m architecture, which has been implemented in the QEMU's `hw/arm/armv7m.c` list; Second, NVIC for armv7m has been implemented in `hw/intc/armv7m_nvic.c`; Third, it is necessary to create a virtual clock in QEMU; Finally, what left to do is to implement UART4 of the board. 

## Structurize picked components

Basically, QEMU allows users to create a device or a machine. A machine is a full-fludged development board with all necessary peripherals connected, like "stm32h7rx7sx-dk"; a device can broadly mean a peripheral (SRAM, Flash, UART, CAN, etc) and a SoC board. Many device examples in QEMU have already been created by engineering effort, e.g., "stm32f100soc". Let us take a device class "stm32f100soc" as an example, the device class is composed of many components, including ARMV7M, ARMV7M_NVIC, UART, SPI. A machine class "stm32vldiscovery" is built upon the device class "stm32f100soc" and a virtual clock. 

Thus, we can refer to those code snippets as a template and create our own devices and machines with less engineering effort. We employ a top-down approach to break up our project structure. We define a machine class "stm32h7rx7sx-dk", which is built upon a soc device class "stm32h7rx7sx_soc". The device class consists of other device classes, including USART, RCC, PWR, CPU, NVIC.

Note that RCC and PWR are automatically created in STM32 code generator, we have to implement two of these, otherwise QEMU will panic when getting access to their corresponding MMIO ranges.

# Implement a SoC device class

For simplicity, I only present some code parts of "stm32h7rx7sx_soc". Interesting readers can consult the GitHub repo for more information. `stm32h7rx7sx_soc_realize` is a function for initialization when the device class is instantialized.

```c
static void stm32h7rx7sx_soc_realize(DeviceState *dev_soc, Error **errp) {
    /* Clock */
    // ...

    /* Memory */
    memory_region_init_rom(&s->flash, OBJECT(dev_soc), "stm32h7rx7sx.flash",
                           FLASH_SIZE, &error_fatal);
    memory_region_init_alias(&s->flash_alias, OBJECT(dev_soc),
                             "stm32h7rx7sx.flash.alias", &s->flash, 0, FLASH_SIZE);
    memory_region_add_subregion(system_memory, FLASH_BASE_ADDRESS, &s->flash);
    memory_region_add_subregion(system_memory, 0, &s->flash_alias);

    memory_region_init_ram(&s->sram, NULL, "stm32h7rx7sx.sram", SRAM_SIZE,
                           &error_fatal);
    memory_region_add_subregion(system_memory, SRAM_BASE_ADDRESS, &s->sram);

    /* Reset and clock controller */
    dev = DEVICE(&s->rcc);
    if (!sysbus_realize(SYS_BUS_DEVICE(&s->rcc), errp)) {
        return;
    }
    busdev = SYS_BUS_DEVICE(dev);
    sysbus_mmio_map(busdev, 0, RCC_ADDR);
    
    /*Power controller*/
    dev = DEVICE(&s->pwr);
    if (!sysbus_realize(SYS_BUS_DEVICE(&s->pwr), errp)) {
        return;
    }
    busdev = SYS_BUS_DEVICE(dev);
    sysbus_mmio_map(busdev, 0, PWR_BASE_ADDRESS);

    /* Attach UART (uses USART registers) and USART controllers */
    for (i = 0; i < STM_NUM_USARTS; i++) {
        dev = DEVICE(&(s->usart[i]));
        // -chardev stdio,id=char0
        qdev_prop_set_chr(dev, "chardev", serial_hd(i));
        if (!sysbus_realize(SYS_BUS_DEVICE(&s->usart[i]), errp)) {
            return;
        }
        busdev = SYS_BUS_DEVICE(dev);
        sysbus_mmio_map(busdev, 0, usart_addr[i]);
        sysbus_connect_irq(busdev, 0, qdev_get_gpio_in(armv7m, usart_irq[i]));
    }

    /* It is necessary to create dummy devices to avoid unassigned memory accesses */
    create_unimplemented_device("GPIOA",       0x58020000, 0x400);
    create_unimplemented_device("GPIOB",       0x58020400, 0x400);
    ...
}
```

## Use a UART device class in SoC

Consult page 159 of [reference_manual_stm32h7rx7sx](https://www.st.com/resource/en/reference_manual/rm0477-stm32h7rx7sx-armbased-32bit-mcus-stmicroelectronics.pdf) to figure out the logic of UART4. We only implement UART4 since it is a debug port and our firmware logic uses for logging. Specifically, UART4 is connected to STLINK-V3SET, allowing the host PC to communicate with the target microcontroller through UART. 

First, its memory map ranges from 0x40004C00 to 0x40004FFF, which is used by `sysbus_mmio_map` in the SoC code base. Be aware that the size of the memory region is defined in the UART device class.

![Image alt]({{ site.baseurl }}/assets/image/2025-07-21-extended-qemu/uart-memory-map.png "Memory map and register boundary addresses for UART")

```c
// stm32h7rx7sx_soc.c
static const uint32_t usart_addr[STM_NUM_USARTS] = { 0x40004C00 };
static const int usart_irq[STM_NUM_USARTS] = {85};
sysbus_mmio_map(busdev, 0, usart_addr[i]);
sysbus_connect_irq(busdev, 0, qdev_get_gpio_in(armv7m, usart_irq[i]));

// stm32h7rx7sx_usart.c
sysbus_init_irq(SYS_BUS_DEVICE(obj), &s->irq);
memory_region_init_io(&s->mmio, obj, &stm32h7rx7sx_usart_ops, s,
                      TYPE_STM32H7RX7SX_USART, 0x400);
```

As the above code snippets presented, I mount UART4 to IRQ 85 according to the page 863 of reference manual. That means whenever a peripheral finishes data transmit over UART4, an interrupt request arises to inform MCU to read out data in a buffer.

Cool, it is clear enough about how a device is utilized in the soc code base. What else do we consider when implementing a peripheral? Basically, QEMU allows developers to create a I/O device by calling `memory_region_init_io` for a device, and developers implement read/write operations whenever a memory access takes place at such a memory region, which is similar to hooking of memory access in the system security domain.

Furthermore, we need to create a struct to preserve states and configuration for the device like the following:
```c
struct XXXState {
    SysBusDevice parent_obj;

    MemoryRegion mmio;

    uint32_t regs[REG_NUMBER]; // preserve states and configuration

    qemu_irq enable_irq[NIRQS];
    qemu_irq reset_irq[NIRQS];
};
```


## Implement an incomplete UART device class

A peripheral operates registers in its MMIO range, and whenever a MMIO access falls into a register, this peripheral should perform corresponding operation and respect the setup. In our case, we care most about those registers, including `USART_TDR`, `USART_CR1`, and `USART_ISR`, as well as some flags like `USART_ISR_TXE`, `USART_ISR_TC`. Hence, it is necessary to implement the logic of dealing with any read/write to those registers. I find it best to refer to reference manual and STM32 HAL code together. Reference manual helps you understand the purpose of each register and flag, while HAL code gets you more sense of how a flag is used to inspect device status. Since I am not supposed to implement a full-fludged UART logic due to high complexity but target at UART transmit. 

The following struct preserves necessary registers and their offsets in the MMIO range.
```c
// 
typedef struct
{
  __IO uint32_t CR1;         /*!< USART Control register 1,                    Address offset: 0x00 */
  __IO uint32_t CR2;         /*!< USART Control register 2,                    Address offset: 0x04 */
  __IO uint32_t CR3;         /*!< USART Control register 3,                    Address offset: 0x08 */
  __IO uint32_t BRR;         /*!< USART Baud rate register,                    Address offset: 0x0C */
  __IO uint32_t GTPR;        /*!< USART Guard time and prescaler register,     Address offset: 0x10 */
  __IO uint32_t RTOR;        /*!< USART Receiver Time Out register,            Address offset: 0x14 */
  __IO uint32_t RQR;         /*!< USART Request register,                      Address offset: 0x18 */
  __IO uint32_t ISR;         /*!< USART Interrupt and status register,         Address offset: 0x1C */
  __IO uint32_t ICR;         /*!< USART Interrupt flag Clear register,         Address offset: 0x20 */
  __IO uint32_t RDR;         /*!< USART Receive Data register,                 Address offset: 0x24 */
  __IO uint32_t TDR;         /*!< USART Transmit Data register,                Address offset: 0x28 */
  __IO uint32_t PRESC;       /*!< USART Prescaler register,                    Address offset: 0x2C */
} USART_TypeDef;
```

In order to get transmit to work, figure out any flags to be used for checking in HAL code. `WordLength` and `Parity` are stored in `USART_CR1` to tell if the size of data is 16-bit or 8-bit.
```c
HAL_StatusTypeDef HAL_UART_Transmit(UART_HandleTypeDef *huart, const uint8_t *pData, uint16_t Size, uint32_t Timeout)
{  
    /* In case of 9bits/No Parity transfer, pData needs to be handled as a uint16_t pointer */
    if ((huart->Init.WordLength == UART_WORDLENGTH_9B) && (huart->Init.Parity == UART_PARITY_NONE)) {
      pdata8bits  = NULL;
      pdata16bits = (const uint16_t *) pData;
    }
    else {
      pdata8bits  = pData;
      pdata16bits = NULL;
    }

    ...
    
    if (pdata8bits == NULL) {
      huart->Instance->TDR = (uint16_t)(*pdata16bits & 0x01FFU);
      pdata16bits++;
    }
    else {
      huart->Instance->TDR = (uint8_t)(*pdata8bits & 0xFFU);
      pdata8bits++;
    }   
}
```

A HAL function `UART_CheckIdleState` will take place during initialization. `USART_ISR_TEACK` should be set in `USART_ISR` when the device gets to reset in QEMU.

```c
// HAL
HAL_StatusTypeDef UART_CheckIdleState(UART_HandleTypeDef *huart)
{
	    /* Wait until TEACK flag is set */
    if (UART_WaitOnFlagUntilTimeout(huart, USART_ISR_TEACK, RESET, tickstart, HAL_UART_TIMEOUT_VALUE) != HAL_OK)
    {
	    ...
    }
}

// QEMU
static void stm32h7rx7sx_usart_reset(DeviceState *dev)
{
    STM32H7RX7SXUsartState *s = STM32H7RX7SX_USART(dev);
    // do hardware setup things
    s->usart_isr = USART_ISR_TEACK | USART_ISR_REACK | USART_ISR_TXE | USART_ISR_TC;
}

```


Another HAL function `UART_WaitOnFlagUntilTimeout` checks if data is available and transmit is completed. Hence, when data is written to `USART_TDR`, `UART_FLAG_TXE` should be in RESET. When accessing to ISR, `UART_FLAG_TXE` should be in SET.
```c
 if (UART_WaitOnFlagUntilTimeout(huart, UART_FLAG_TXE, RESET, tickstart, Timeout) != HAL_OK)
 {
    huart->gState = HAL_UART_STATE_READY;
    huart->Instance->TDR = data;
 }
 
if (UART_WaitOnFlagUntilTimeout(huart, UART_FLAG_TC, RESET, tickstart, Timeout) != HAL_OK)
{
	huart->gState = HAL_UART_STATE_READY;
	
	return HAL_TIMEOUT;
}
```

## Implement RCC device class

According to reference manual, RCC refers to Reset and clock control, which manages the clock and reset generation for the whole microcontroller. Its memory region ranges from 0x58024400 to 0x580247FF. In our firmware project, if RCC is not implemented properly, `SystemCoreClockUpdate` will crash execution.

```c
  void SystemCoreClockUpdate(void){
	  switch (RCC->CFGR & RCC_CFGR_SWS) // will crash
  }
```

It is easier to implement RCC that we simply store a value in a corresponding register and return a value when there is an access to it. To keep the code neat, I remove some checking:
```c
static uint64_t stm32h7rsxx_rcc_read(void *opaque, hwaddr addr, unsigned int size) {
    return s->regs[addr >> 2];
}

static void stm32h7rsxx_rcc_write(void *opaque, hwaddr addr, uint64_t val64, unsigned int size) {
    s->regs[addr / 4] = value;
}
```


## Implement PWR device class

When it comes to Power control (PWR), it provides an overview of the supply architecture for the
different power domains and of the supply configuration controller. Its memory region ranges from 0x58024800 to 0x58024BFF. During initializaion, a HAL function will check if some flags are set in the PWR memory region.

```c
HAL_StatusTypeDef HAL_PWREx_EnableUSBVoltageDetector(void)
{
  uint32_t tickstart;

  /* Enable the USB voltage detector */
  SET_BIT(PWR->CSR2, PWR_CSR2_USB33DEN);

  /* Get tick */
  tickstart = HAL_GetTick();

  /* Wait till the USB regulator ready flag is set */
  while ((PWR->CSR2 & PWR_CSR2_USB33RDY) == 0U)
  {
    if ((HAL_GetTick() - tickstart) > PWR_FLAG_SETTING_DELAY)
    {
      return HAL_ERROR;
    }
  }
  return HAL_OK;
}
```

Since we do not intend for a full PWR logic, it is necessary to return a value with USB regulator ready flag set like the following:
```c
static uint64_t stm32h7s7xx_pwr_read(void *opaque, hwaddr addr, unsigned int size)
{
    STM32H7S7XXPWRState *s = STM32H7S7XX_PWR(opaque);
    uint32_t value = s->regs[addr >> 2];

    if (addr == STM32H7S7XX_PWR_CSR2)
        return value | PWR_CSR2_USB33RDY;
    
    return value;
}
```

# Build the QEMU from source

I build such a custom QEMU in Ubuntu 22:04 and am asked to install dependencies before a build as following:
```bash
sudo apt install git libglib2.0-dev libgcrypt20-dev zlib1g-dev autoconf automake libtool bison flex libpixman-1-dev python3-venv meson cmake python3-pip llvm
```

The proceeding commmand for configuration. Note that you may need to enable trace for debugging.
```bash
mkdir build
cd build
../configure --target-list=arm-softmmu --enable-debug --enable-trace-backends=simple
make -j(nproc)
```

# Emulate the firmware binary

Once the QEMU is built, use the following command to test if emulation works.

```bash
user@341b44abc943:~/qemu/build$ ./qemu-system-arm --version
QEMU emulator version 10.0.2
user@341b44abc943:~/qemu/build$ ./qemu-system-arm -M stm32h7rx7sx_dk -display none -kernel ~/stm32-cubemx.elf -chardev stdio,id=char0 -serial chardev:char0 -D qemu.log -d guest_errors
testing branch #1...
testing branch #1...
testing branch #1...
testing branch #1...
```

## Why another testing branch is not taken?

This is an interesting question. A string "testing branch #0" should have been printed out. Why does it never show up? Upon checking into the firmware logic, the value returned by `rand()` should determine which branch to be taken. The current log seems like that the function always emits the same value.

I did reverse engineering on the generated firmware binary with Ghidra and found the random seed comes from `__aeabi_read_tp`. It turns out that the variable `__tls` located at ram determines such a seed generation. However, I did not set up SRAM as an IO memory region. So, it may ask for a trick to implement a hook callback that returns a real random number whenever there is a memory access to this variable. 

```c
 long rand(void)

{
  longlong lVar1;
  undefined4 in_r0;
  int iVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  undefined8 uVar6;
  
  uVar6 = __aeabi_read_tp(in_r0,8);
  iVar3 = (int)((ulonglong)uVar6 >> 0x20);
  iVar2 = (int)uVar6;
  uVar4 = *(uint *)(iVar2 + iVar3);
  lVar1 = (ulonglong)uVar4 * 0x4c957f2d;
  uVar5 = (uint)lVar1;
  *(uint *)(iVar2 + iVar3) = uVar5 + 1;
  uVar4 = *(int *)(iVar2 + iVar3 + 4) * 0x4c957f2d +
          uVar4 * 0x5851f42d + (int)((ulonglong)lVar1 >> 0x20) + (uint)(0xfffffffe < uVar5);
  *(uint *)(iVar2 + iVar3 + 4) = uVar4;
  return uVar4 & 0x7fffffff;
}

undefined4 __aeabi_read_tp(void)
{
  return __tls;
}
```


