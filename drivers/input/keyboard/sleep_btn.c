/*
 * Driver for keys on GPIO lines capable of generating interrupts.
 *
 * Copyright 2005 Phil Blundell
 * Copyright 2010, 2011 David Jander <david@protonic.nl>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/sched.h>
#include <linux/pm.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/delay.h>
#include <linux/platform_device.h>
#include <linux/input.h>
#include <linux/gpio_keys.h>
#include <linux/workqueue.h>
#include <linux/gpio.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/of_gpio.h>
#include <linux/of_irq.h>
#include <linux/spinlock.h>

struct sleep_btn_data {
	const struct gpio_keys_button *button;
	unsigned int software_debounce;	/* in msecs, for GPIO-driven buttons */
	unsigned int irq;
	spinlock_t lock;
	bool key_pressed;
};

struct sleep_btn_drvdata {
	const struct gpio_keys_platform_data *pdata;
	struct sleep_btn_data data[0];
};

static irqreturn_t sleep_btn_irq_isr(int irq, void *dev_id)
{
	struct sleep_btn_data *bdata = dev_id;
	unsigned long flags;

	BUG_ON(irq != bdata->irq);

	spin_lock_irqsave(&bdata->lock, flags);

	if (!bdata->key_pressed) {
		//TODO::turnoff backlight
printk("sleep btn first pressed!\n");
		bdata->key_pressed = true;
	}
	else {
		//TODO::turnon backlight
printk("sleep btn second pressed!\n");
		bdata->key_pressed = false;
	}
	
	spin_unlock_irqrestore(&bdata->lock, flags);
	return IRQ_HANDLED;
}

static int sleep_btn_setup_key(struct platform_device *pdev,
				struct sleep_btn_data *bdata,
				const struct gpio_keys_button *button)
{
	const char *desc = button->desc ? button->desc : "sleep-btn";
	struct device *dev = &pdev->dev;
	irq_handler_t isr;
	unsigned long irqflags;
	int irq;
	int error;

	bdata->button = button;
	spin_lock_init(&bdata->lock);

	if (gpio_is_valid(button->gpio)) {

		error = devm_gpio_request_one(&pdev->dev, button->gpio,
					      GPIOF_IN, desc);
		if (error < 0) {
			dev_err(dev, "Failed to request GPIO %d, error %d\n",
				button->gpio, error);
			return error;
		}

		if (button->debounce_interval) {
			error = gpio_set_debounce(button->gpio,
					button->debounce_interval * 1000);
			/* use timer if gpiolib doesn't provide debounce */
			if (error < 0)
				bdata->software_debounce =
						button->debounce_interval;
		}

		if (button->irq) {
			bdata->irq = button->irq;
		} else {
			irq = gpio_to_irq(button->gpio);
			if (irq < 0) {
				error = irq;
				dev_err(dev,
					"Unable to get irq number for GPIO %d, error %d\n",
					button->gpio, error);
				return error;
			}
			bdata->irq = irq;
		}

		isr = sleep_btn_irq_isr;
		irqflags = IRQF_TRIGGER_FALLING;

		/*
		 * If platform has specified that the button can be disabled,
		 * we don't want it to share the interrupt line.
		 */
		if (!button->can_disable)
			irqflags |= IRQF_SHARED;

		error = devm_request_any_context_irq(&pdev->dev, bdata->irq,
						     isr, irqflags, desc, bdata);
		if (error < 0) {
			dev_err(dev, "Unable to claim irq %d; error %d\n",
				bdata->irq, error);
			return error;
		}
	} 

	return 0;
}

/*
 * Handlers for alternative sources of platform_data
 */

#ifdef CONFIG_OF
/*
 * Translate OpenFirmware node properties into platform_data
 */
static struct gpio_keys_platform_data *
sleep_btn_get_devtree_pdata(struct device *dev)
{
	struct device_node *node, *pp;
	struct gpio_keys_platform_data *pdata;
	struct gpio_keys_button *button;
	int error;
	int nbuttons;
	int i;

	node = dev->of_node;
	if (!node)
		return ERR_PTR(-ENODEV);

	nbuttons = of_get_child_count(node);
	if (nbuttons == 0)
		return ERR_PTR(-ENODEV);

	pdata = devm_kzalloc(dev,
			     sizeof(*pdata) + nbuttons * sizeof(*button),
			     GFP_KERNEL);
	if (!pdata)
		return ERR_PTR(-ENOMEM);

	pdata->buttons = (struct gpio_keys_button *)(pdata + 1);
	pdata->nbuttons = nbuttons;

	i = 0;
	for_each_child_of_node(node, pp) {
		enum of_gpio_flags flags;

		button = &pdata->buttons[i++];

		button->gpio = of_get_gpio_flags(pp, 0, &flags);
		if (button->gpio < 0) {
			error = button->gpio;
			if (error != -ENOENT) {
				if (error != -EPROBE_DEFER)
					dev_err(dev,
						"Failed to get gpio flags, error: %d\n",
						error);
				return ERR_PTR(error);
			}
		} else {
			button->active_low = flags & OF_GPIO_ACTIVE_LOW;
		}

		button->irq = irq_of_parse_and_map(pp, 0);

		if (!gpio_is_valid(button->gpio) && !button->irq) {
			dev_err(dev, "Found button without gpios or irqs\n");
			return ERR_PTR(-EINVAL);
		}

		if (of_property_read_u32(pp, "linux,code", &button->code)) {
			dev_err(dev, "Button without keycode: 0x%x\n",
				button->gpio);
			return ERR_PTR(-EINVAL);
		}

		button->desc = of_get_property(pp, "label", NULL);

		if (of_property_read_u32(pp, "linux,input-type", &button->type))
			button->type = EV_KEY;

		if (of_property_read_u32(pp, "debounce-interval",
					 &button->debounce_interval))
			button->debounce_interval = 5;
	}

	if (pdata->nbuttons == 0)
		return ERR_PTR(-EINVAL);

	return pdata;
}

static const struct of_device_id sleep_btn_of_match[] = {
	{ .compatible = "sleep-btn", },
	{ },
};
MODULE_DEVICE_TABLE(of, sleep_btn_of_match);

#else

static inline struct gpio_keys_platform_data *
sleep_btn_get_devtree_pdata(struct device *dev)
{
	return ERR_PTR(-ENODEV);
}

#endif

static int sleep_btn_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	const struct gpio_keys_platform_data *pdata = dev_get_platdata(dev);
	struct sleep_btn_drvdata *ddata;
	size_t size;
	int i, error;

	if (!pdata) {
		pdata = sleep_btn_get_devtree_pdata(dev);
		if (IS_ERR(pdata))
			return PTR_ERR(pdata);
	}

	size = sizeof(struct sleep_btn_drvdata) +
			pdata->nbuttons * sizeof(struct sleep_btn_data);
	ddata = devm_kzalloc(dev, size, GFP_KERNEL);
	if (!ddata) {
		dev_err(dev, "failed to allocate state\n");
		return -ENOMEM;
	}
	ddata->pdata = pdata;

	for (i = 0; i < pdata->nbuttons; i++) {
		const struct gpio_keys_button *button = &pdata->buttons[i];
		struct sleep_btn_data *bdata = &ddata->data[i];

		error = sleep_btn_setup_key(pdev, bdata, button);
		if (error)
			return error;
	}

	platform_set_drvdata(pdev, ddata);
	device_init_wakeup(&pdev->dev, 1);

	return 0;
}

static int sleep_btn_remove(struct platform_device *pdev)
{
	device_init_wakeup(&pdev->dev, 0);

	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int sleep_btn_suspend(struct device *dev)
{
	struct sleep_btn_drvdata *ddata = dev_get_drvdata(dev);
	int i;

	if (device_may_wakeup(dev)) {
		for (i = 0; i < ddata->pdata->nbuttons; i++) {
			struct sleep_btn_data *bdata = &ddata->data[i];
			if (bdata->button->wakeup)
				enable_irq_wake(bdata->irq);
		}
	}

	return 0;
}

static int sleep_btn_resume(struct device *dev)
{
	struct sleep_btn_drvdata *ddata = dev_get_drvdata(dev);
	int i;

	if (device_may_wakeup(dev)) {
		for (i = 0; i < ddata->pdata->nbuttons; i++) {
			struct sleep_btn_data *bdata = &ddata->data[i];
			if (bdata->button->wakeup)
				disable_irq_wake(bdata->irq);
		}
	}

	return 0;
}
#endif

static SIMPLE_DEV_PM_OPS(sleep_btn_pm_ops, sleep_btn_suspend, sleep_btn_resume);

static struct platform_driver sleep_btn_device_driver = {
	.probe		= sleep_btn_probe,
	.remove		= sleep_btn_remove,
	.driver		= {
		.name	= "sleep-btn",
		.pm	= &sleep_btn_pm_ops,
		.of_match_table = of_match_ptr(sleep_btn_of_match),
	}
};

static int __init sleep_btn_init(void)
{
	return platform_driver_register(&sleep_btn_device_driver);
}

static void __exit sleep_btn_exit(void)
{
	platform_driver_unregister(&sleep_btn_device_driver);
}

late_initcall(sleep_btn_init);
module_exit(sleep_btn_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Phil Blundell <pb@handhelds.org>");
MODULE_DESCRIPTION("sleep btn driver for GPIO");
