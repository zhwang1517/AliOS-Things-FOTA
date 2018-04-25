#include "mx_debug.h"
#include "mx_common.h"
#include "alicloud_sds.h"

#include "drv_board.h"
#include "main.h"
/* DriverLib Includes */
#include "driverlib.h"
#include "io_button.h"

const emh_alisds_config_t alisds_config =
{
	.product_info = {
		.name      = "tideveloper-001",
		.module      = "TI_LIVING_AIRBOX_TIDEVELOPER_001",
		.key      = "0sB7jw6J4NA0HJGJfwrj",
		.secret      = "r2jU6xdI8Itq7LqBzXI3HMvSPG8pJo35bXb1mcF9",
		.format      = EMH_ARG_ALISDS_FORMAT_JSON,
	},
	.dev_info = {
		.type      = "AIRBOX",
		.category    = "LIVING",
		.manufacture  = "TI",
	}
};

void usr_btn_isr(void);
void usr_clicked_handler(void);
void usr_long_pressed_handler(void);
void PORT4_IRQHandler(void);

btn_instance_t usr_btn =
{
	.port                   = GPIO_PORT_P4,
	.pin                    = GPIO_PIN6,
	.io_irq                 = PORT4_IRQHandler,
	.idle			        = IOBUTTON_IDLE_STATE_HIGH,
	.long_pressed_timeout   = 5000,
	.pressed_func           = usr_clicked_handler,
	.long_pressed_func		= usr_long_pressed_handler,
};

void PORT4_IRQHandler(void)
{
    uint32_t status;

    status = MAP_GPIO_getInterruptStatus(GPIO_PORT_P4,0xFFFF);
    MAP_GPIO_clearInterruptFlag(GPIO_PORT_P4, status);

    /* Toggling the output on the LED */
    if(status & GPIO_PIN6)
    {
    		button_irq_handler(&usr_btn);
    }

}

void usr_clicked_handler(void)
{
	alisds_provision();
}

void usr_long_pressed_handler(void)
{
	app_log("Restore default settings");
	
	OLED_ShowStatusString("Restore default");
	
	alisds_restore();
}

int _main(void)
{
	mx_status err = kNoErr;

	drv_board_init();
	drv_board_test();

	OLED_ShowString(OLED_DISPLAY_COLUMN_START, OLED_DISPLAY_ROW_1, "TI University");

	err = alisds_init(&alisds_config, ALI_HANDLE_MAX);
	require_noerr(err, exit);
	

	rgbled_task_init();
	SHT20_task_init();
	switch_task_init();
	console_task_init();
	
	button_init(&usr_btn);

	while(1)
	{
		/* Application tick */
		alisds_runloop();
		SHT20_task();
		switch_task();
		button_srv(&usr_btn);
	}
	
exit:
	app_log("App exit reason %d", err);
	while(1);
}

//================================================================
//						OS entry
//================================================================
#include "k_api.h"
#include <stdio.h>
#include <stdlib.h>

#define DEMO_TASK_STACKSIZE    1024
#define DEMO_TASK_PRIORITY     20

extern void stm32_soc_init(void);
static ktask_t demo_task_obj;
cpu_stack_t demo_task_buf[DEMO_TASK_STACKSIZE];

void demo_task(void *arg)
{
#if 0
    int count = 0;

    printf("demo_task here!\n");
    printf("rhino memory is %d!\n", krhino_global_space_get());

    while (1)
    {
        printf("hello world! count %d\n", count++);
        //sleep 1 second
        krhino_task_sleep(1000);
    };
#else
    _main();
#endif
}

void soc_init(void)
{
	mx_hal_stdio_init();
	SysTick_Config(SystemCoreClock / 1000);
}

int main(void)
{
	soc_init();

    krhino_init();

    krhino_task_create(&demo_task_obj, "demo_task", 0,DEMO_TASK_PRIORITY, 
        50, demo_task_buf, DEMO_TASK_STACKSIZE, demo_task, 1);
    
    krhino_start();
    
    return 0;
}

//================================================================
//						OS ports
//================================================================
void SysTick_Handler(void)
{
  _SysTick_Handler();
  krhino_intrpt_enter();
  krhino_tick_proc();
  krhino_intrpt_exit();
}

//================================================================
//						libc stubs
//================================================================
size_t _write( int handle, const unsigned char * buffer, size_t size )
{
  	uint32_t i;
	for (i = 0; i < size; i++){
		while (EUSCI_A_UART_TRANSMIT_INTERRUPT & MAP_UART_getEnabledInterruptStatus(EUSCI_A0_BASE));
		MAP_UART_transmitData(EUSCI_A0_BASE, *(buffer++));
	}
  	return size;
}

extern unsigned char _end[];
static unsigned char *sbrk_heap_top = _end;
caddr_t _sbrk( int incr )
{
    unsigned char *prev_heap;

    prev_heap = sbrk_heap_top;

    sbrk_heap_top += incr;

    return (caddr_t) prev_heap;
}
