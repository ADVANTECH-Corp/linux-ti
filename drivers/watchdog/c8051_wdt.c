/*
 * C8051 Watchdog driver
 */

#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/platform_device.h>
#include <linux/watchdog.h>
#include <linux/reboot.h>
#include <linux/notifier.h>
#include <linux/i2c.h>
#include <linux/of_gpio.h>
#include <asm/system_misc.h>

#define C8051_WDT_WCR		0x00		/* Control Register */
#define C8051_WDT_WCR_WT		(0xFF << 8)	/* -> Watchdog Timeout Field */
#define C8051_WDT_WCR_WRE	(1 << 3)	/* -> WDOG Reset Enable */
#define C8051_WDT_WCR_WDE	(1 << 2)	/* -> Watchdog Enable */
#define C8051_WDT_WCR_WDZST	(1 << 0)	/* -> Watchdog timer Suspend */

#define C8051_WDT_WRSR		0x04		/* Reset Status Register */
#define C8051_WDT_WRSR_TOUT	(1 << 1)	/* -> Reset due to Timeout */

#define C8051_WDT_MIN_TIME	1
#define C8051_WDT_MAX_TIME	65535
#define C8051_WDT_DEFAULT_TIME	30		/* in seconds */
#define C8051_WDT_DEFAULT_SHUTDOWN_TIME	3		/* in seconds */

#define WDOG_SEC_TO_COUNT(s)	(s * 10) //Time unite: 100ms -> 1s

#define REG_WDT_WATCHDOG_TIME_OUT	0x15
#define REG_WDT_CMD 		0x16
#define REG_WDT_CMD_POWEROFF	1
#define REG_WDT_CMD_REBOOT	2
#define REG_WDT_REMAIN_TIME_OUT		0x25
#define REG_WDT_VERSION 				0x27
#define REG_WDT_SHUTDOWN_TIME		0x17

//#define C8051_UNSUPPORT_FEATURE

#define DRIVER_NAME "c8051-wdt-i2c"

struct c8051_wdt_priv {
	bool active_high;
	bool wdt_ping_status;
	unsigned int shudwon_time;
	unsigned int gpio_wdt_en;
	unsigned int gpio_wdt_pwm;
	unsigned int default_enable;
	struct notifier_block	notifier;
	struct watchdog_device	wdd;
	struct i2c_client *iic_client;
};

static struct i2c_client *client_c8051 = NULL;
static unsigned timeout = C8051_WDT_DEFAULT_TIME;
module_param(timeout, uint, 0);
MODULE_PARM_DESC(timeout, "Watchdog timeout in seconds (default="
				__MODULE_STRING(C8051_WDT_DEFAULT_TIME) ")");

static unsigned int shutdown_time = C8051_WDT_DEFAULT_SHUTDOWN_TIME;
module_param(shutdown_time, uint, 0);
MODULE_PARM_DESC(shutdown_time, "C8051 default shutdown timeout in seconds (default="
				__MODULE_STRING(C8051_WDT_DEFAULT_SHUTDOWN_TIME) ")");

struct watchdog_info c8051_wdt_info = {
	.identity = "C8051 watchdog",
	.options = WDIOF_KEEPALIVEPING | WDIOF_SETTIMEOUT | WDIOF_MAGICCLOSE,
	.firmware_version = 0,
};

static int c8051_wdt_i2c_write_reg(struct i2c_client *client, u8 reg, void *buf, size_t len)
{
	u8 val[1 + len];
	struct i2c_msg msg[1] = {
		{
			.addr = client->addr,
			.flags = 0,
			.len = sizeof(val),
			.buf = val,
		}
	};

	val[0] = reg;
	memcpy(&val[1], buf, len);

	if (i2c_transfer(client->adapter, msg, 1) != 1) {
		dev_err(&client->dev, "c8051_wdt_i2c_write: i2c transfer failed\n");
		return -EIO;
	}
	
	return 0;
}

static int c8051_wdt_i2c_read_reg(struct i2c_client *client, u8 reg, void *buf, size_t len)
{
	struct i2c_msg msg[2] = {
		{
			.addr	= client->addr,
			.flags	= 0,
			.len	= 1,
			.buf	= &reg,
		},
		{
			.addr	= client->addr,
			.flags	= I2C_M_RD,
			.len	= len,
			.buf	= buf,
		}
	};

	if (i2c_transfer(client->adapter, msg, 2) != 2) {
		dev_err(&client->dev, "c8051_wdt_i2c_read: i2c transfer failed\n");
		return -EIO;
	}
	
	return 0;
}

static int c8051_wdt_i2c_set_timeout(struct i2c_client *client, u16 val)
{
	int ret = 0;
	
	//val = WDOG_SEC_TO_COUNT(val);
	ret = c8051_wdt_i2c_write_reg(client, REG_WDT_WATCHDOG_TIME_OUT, &val, sizeof(val));
	if (ret)
		return -EIO;
	return 0;
}

static int c8051_wdt_i2c_read_version(struct i2c_client *client, u16 *val)
{
	int ret = 0;
	
	ret = c8051_wdt_i2c_read_reg(client, REG_WDT_VERSION, val, sizeof(val));
	if (ret)
		return -EIO;
	return 0;
}

static int c8051_wdt_ping(struct watchdog_device *wdd)
{
	struct c8051_wdt_priv *priv = watchdog_get_drvdata(wdd);

	priv->wdt_ping_status = !priv->wdt_ping_status;
	gpio_set_value_cansleep(priv->gpio_wdt_pwm, priv->wdt_ping_status);

	return 0;
}

static int c8051_wdt_set_timeout(struct watchdog_device *wdd, unsigned int t)
{
	struct c8051_wdt_priv *priv = watchdog_get_drvdata(wdd);
	wdd->timeout = t;
	c8051_wdt_i2c_set_timeout(priv->iic_client, t);
	c8051_wdt_ping(wdd);
	
	return 0;
}

static int c8051_wdt_set_shutdown_time(struct i2c_client *client, u8 val)
{
	int ret = 0;
	
	ret = c8051_wdt_i2c_write_reg(client, REG_WDT_SHUTDOWN_TIME, &val, 1);
	if (ret)
		return -EIO;
	return 0;
}

static void c8051_reboot(enum reboot_mode reboot_mode, const char *cmd)
{
	unsigned char val = REG_WDT_CMD_REBOOT;

	printk("%s...\n",__func__);
	if(client_c8051)
		c8051_wdt_i2c_write_reg(client_c8051, REG_WDT_CMD, &val, sizeof(val));
}

static void c8051_prepare_poweroff(void)
{
	unsigned char val = REG_WDT_CMD_POWEROFF;

	printk("%s...\n",__func__);
	if(client_c8051)
		c8051_wdt_i2c_write_reg(client_c8051, REG_WDT_CMD, &val, sizeof(val));
}

#ifdef C8051_UNSUPPORT_FEATURE
int c8051_wdt_i2c_read_remain_time(struct i2c_client *client, unsigned int *val)
{
	int ret = 0;
	
	ret = c8051_wdt_i2c_read_reg(client, REG_WDT_REMAIN_TIME_OUT, val, sizeof(val));
	if (ret)
		return -EIO;
	return 0;
}

static unsigned int c8051_wdt_get_timeleft(struct watchdog_device *wdd)
{
	struct c8051_wdt_priv *priv = watchdog_get_drvdata(wdd);
	c8051_wdt_i2c_read_remain_time(priv->iic_client, &wdd->timeout);

	return 0;
}
#endif

static int c8051_wdt_start(struct watchdog_device *wdd)
{
	struct c8051_wdt_priv *priv = watchdog_get_drvdata(wdd);
	gpio_set_value_cansleep(priv->gpio_wdt_en, priv->active_high);

	/* Watchdog is enabled - time to reload the timeout value */
	c8051_wdt_i2c_set_timeout(priv->iic_client, priv->wdd.timeout);
	c8051_wdt_ping(wdd);

	return 0;
}

static int c8051_wdt_stop(struct watchdog_device *wdd)
{
	struct c8051_wdt_priv *priv = watchdog_get_drvdata(wdd);
	/* we don't need a clk_disable, it cannot be disabled once started.
	 * We use a timer to ping the watchdog while /dev/watchdog is closed */
	gpio_set_value_cansleep(priv->gpio_wdt_en, !priv->active_high);

	return 0;
}

static const struct watchdog_ops c8051_wdt_fops = {
	.owner		= THIS_MODULE,
	.start		= c8051_wdt_start,
	.stop		= c8051_wdt_stop,
	.ping		= c8051_wdt_ping,
	.set_timeout	= c8051_wdt_set_timeout,
#ifdef C8051_UNSUPPORT_FEATURE
	.get_timeleft	= c8051_wdt_get_timeleft,
#endif
};

static int c8051_wdt_notify_sys(struct notifier_block *nb, unsigned long code,
			       void *unused)
{
	struct c8051_wdt_priv *priv = container_of(nb, struct c8051_wdt_priv, notifier);

	switch (code) {
	case SYS_HALT:
	case SYS_POWER_OFF:
		c8051_wdt_stop(&priv->wdd);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

static int c8051_wdt_i2c_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	struct c8051_wdt_priv *priv;
	int ret;
	u16 tmp_version;
	struct device_node *np = client->dev.of_node;
	enum of_gpio_flags flags;

	if (!np)
	{
		return -ENODEV;
	}

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C))
	{
		return -ENODEV;
	}	

	priv = devm_kzalloc(&client->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	i2c_set_clientdata(client, priv);
	priv->iic_client = client;

	ret = of_property_read_u32(np, "default-enable",&priv->default_enable);
	if (ret < 0) {
		priv->default_enable = 0;
		dev_warn(&client->dev, "request default-enable failed,diable watchdog\n");
	}

	//Setting GPIO
	priv->gpio_wdt_pwm = of_get_named_gpio_flags(np, "wdt-pwm", 0, &flags);
	if (!gpio_is_valid(priv->gpio_wdt_pwm))
		return -ENODEV;
	ret = devm_gpio_request_one(&client->dev, priv->gpio_wdt_pwm, 
				GPIOF_OUT_INIT_LOW, "c8051_wdt.wdt_pwm");
	if (ret < 0) {
		dev_err(&client->dev, "request gpio failed: %d\n", ret);
		return ret;
	}

	priv->gpio_wdt_en = of_get_named_gpio_flags(np, "wdt-en", 0, &flags);
	if (!gpio_is_valid(priv->gpio_wdt_en))
		return -ENODEV;	
	priv->active_high = !(flags & OF_GPIO_ACTIVE_LOW);
	priv->wdt_ping_status = priv->active_high;
	ret = devm_gpio_request_one(&client->dev, priv->gpio_wdt_en,
				(priv->default_enable ^ priv->active_high) ? GPIOF_OUT_INIT_LOW : GPIOF_OUT_INIT_HIGH, "c8051_wdt.wdt_en");
	if (ret < 0) {
		dev_err(&client->dev, "request gpio failed: %d\n", ret);
		return ret;
	}
	//gpio_direction_output(priv->gpio_wdt_en, priv->active_high);
	//gpio_direction_output(priv->gpio_wdt_pwm, priv->wdt_ping_status);

	ret = of_property_read_u32(np, "shutdown-time",&priv->shudwon_time);
	if (ret < 0) {
		priv->shudwon_time = shutdown_time;
		dev_warn(&client->dev, "request shutdown-time failed,using default time:%ds\n", shutdown_time);
	}
	c8051_wdt_set_shutdown_time(client,priv->shudwon_time);

	ret = c8051_wdt_i2c_read_version(client, &tmp_version);
	c8051_wdt_info.firmware_version = tmp_version;

	watchdog_set_drvdata(&priv->wdd, priv);

	priv->wdd.parent	= &client->dev;
	priv->wdd.info		= &c8051_wdt_info;
	priv->wdd.ops		= &c8051_wdt_fops;
	priv->wdd.min_timeout	= C8051_WDT_MIN_TIME;
	priv->wdd.max_timeout	= C8051_WDT_MAX_TIME;
	priv->wdd.timeout = clamp_t(unsigned, timeout, C8051_WDT_MIN_TIME, C8051_WDT_MAX_TIME);
	if (priv->wdd.timeout != timeout)
		dev_warn(&client->dev, "Initial timeout out of range! "
			"Clamped from %u to %u\n", timeout, priv->wdd.timeout);

	ret = watchdog_register_device(&priv->wdd);
	if (ret)
		return ret;

	priv->notifier.notifier_call = c8051_wdt_notify_sys;
	ret = register_reboot_notifier(&priv->notifier);
	if (ret)
		goto error_unregister;

	dev_info(&client->dev,"C8051 Watchdog Timer enabled. timeout=%ds, Ver.%d\n",
						priv->wdd.timeout, c8051_wdt_info.firmware_version);

	client_c8051 = client;
	arm_pm_restart = c8051_reboot;
	pm_power_off_prepare = c8051_prepare_poweroff;

	return 0;

error_unregister:
	watchdog_unregister_device(&priv->wdd);
	return ret;

}

static int __exit c8051_wdt_i2c_remove(struct i2c_client *client)
{
	struct c8051_wdt_priv *priv;

	priv=i2c_get_clientdata(client);
	
	unregister_reboot_notifier(&priv->notifier);
	watchdog_unregister_device(&priv->wdd);

	gpio_set_value_cansleep(priv->gpio_wdt_en, !priv->active_high);
	dev_crit(priv->wdd.parent, "Device removed: Expect reboot!\n");
	
	return 0;
}

static void c8051_wdt_i2c_shutdown(struct i2c_client *client)
{
	struct c8051_wdt_priv *priv;

	priv=i2c_get_clientdata(client);
	gpio_set_value_cansleep(priv->gpio_wdt_en, !priv->active_high);
}

static const struct i2c_device_id c8051_wdt_i2c_id[] = {
	{DRIVER_NAME, 0},
	{},
};

MODULE_DEVICE_TABLE(i2c, c8051_wdt_i2c_id);

static const struct of_device_id c8051_wdt_i2c_dt_ids[] = {
	{ .compatible = "c8051-wdt-i2c", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, c8051_wdt_i2c_dt_ids);

static struct i2c_driver c8051_wdt_i2c_driver = {
	.driver = {
		   .name = DRIVER_NAME,
		   .owner = THIS_MODULE,
		   .of_match_table = c8051_wdt_i2c_dt_ids,
	},
	.probe = c8051_wdt_i2c_probe,
	.remove = c8051_wdt_i2c_remove,
	.shutdown	= c8051_wdt_i2c_shutdown,
	.id_table = c8051_wdt_i2c_id,
};

static int __init c8051_wdt_i2c_init(void)
{
	return i2c_add_driver(&c8051_wdt_i2c_driver);
}

static void __exit c8051_wdt_i2c_exit(void)
{
	i2c_del_driver(&c8051_wdt_i2c_driver);
}

module_init(c8051_wdt_i2c_init);
module_exit(c8051_wdt_i2c_exit);

MODULE_DESCRIPTION("C8051 Watchdog I2C Driver");
MODULE_LICENSE("GPL");
