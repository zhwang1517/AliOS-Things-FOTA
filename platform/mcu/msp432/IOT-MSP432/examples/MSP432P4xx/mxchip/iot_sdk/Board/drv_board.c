
#include <stdio.h>
#include "drv_board.h"

void drv_board_init(void)
{
	/* RGB color led initialize */
	color_led_init();
	color_led_open_rgb(0, 0, 0);

	/* Temperature and humidity sensor  */
	SHT2x_Init();

	/* init OLED */
	OLED_Init();
	OLED_Clear();
	
}
