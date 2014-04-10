/* kernel/power/earlysuspend.c
 *
 * Copyright (C) 2005-2008 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/earlysuspend.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rtc.h>
#include <linux/wakelock.h>
#include <linux/workqueue.h>

/*KERNEL-SC-SUSPEND_RESUME_WAKELOCK_LOG-01+[ */
#ifdef CONFIG_FIH_SUSPEND_RESUME_LOG
#include <linux/syscalls.h> /* sys_sync */
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#include <linux/kallsyms.h>
#endif
/*KERNEL-SC-SUSPEND_RESUME_WAKELOCK_LOG-01+] */
#include "power.h"


/*FIH-KERNEL-SC-Suspend_Hang_Timer-00+[*/
#ifdef CONFIG_FIH_SUSPEND_HANG_TIMER
#include <linux/timer.h>
extern struct timer_list suspend_hang_timer;
extern pid_t pid_suspend;
extern int suspend_dump_counter;
#endif
/*FIH-KERNEL-SC-Suspend_Hang_Timer-00+]*/

enum {
	DEBUG_USER_STATE = 1U << 0,
	DEBUG_SUSPEND = 1U << 2,
	DEBUG_VERBOSE = 1U << 3,
};
static int debug_mask = DEBUG_USER_STATE;
module_param_named(debug_mask, debug_mask, int, S_IRUGO | S_IWUSR | S_IWGRP);

static DEFINE_MUTEX(early_suspend_lock);
static LIST_HEAD(early_suspend_handlers);
static void early_suspend(struct work_struct *work);
static void late_resume(struct work_struct *work);
static DECLARE_WORK(early_suspend_work, early_suspend);
static DECLARE_WORK(late_resume_work, late_resume);
static DEFINE_SPINLOCK(state_lock);
enum {
	SUSPEND_REQUESTED = 0x1,
	SUSPENDED = 0x2,
	SUSPEND_REQUESTED_AND_SUSPENDED = SUSPEND_REQUESTED | SUSPENDED,
};
static int state;

void register_early_suspend(struct early_suspend *handler)
{
	struct list_head *pos;

	mutex_lock(&early_suspend_lock);
	list_for_each(pos, &early_suspend_handlers) {
		struct early_suspend *e;
		e = list_entry(pos, struct early_suspend, link);
		if (e->level > handler->level)
			break;
	}
	list_add_tail(&handler->link, pos);
	if ((state & SUSPENDED) && handler->suspend)
		handler->suspend(handler);
	mutex_unlock(&early_suspend_lock);
}
EXPORT_SYMBOL(register_early_suspend);

void unregister_early_suspend(struct early_suspend *handler)
{
	mutex_lock(&early_suspend_lock);
	list_del(&handler->link);
	mutex_unlock(&early_suspend_lock);
}
EXPORT_SYMBOL(unregister_early_suspend);

static void early_suspend(struct work_struct *work)
{
	struct early_suspend *pos;
	unsigned long irqflags;
	int abort = 0;

/*KERNEL-SC-SUSPEND_RESUME_WAKELOCK_LOG-01+[ */
#ifdef CONFIG_FIH_SUSPEND_RESUME_LOG
    ktime_t calltime, delta, rettime;
    unsigned long long duration;
#endif
/*KERNEL-SC-SUSPEND_RESUME_WAKELOCK_LOG-01+] */

/*FIH-KERNEL-SC-Suspend_Hang_Timer-00+[*/
#ifdef CONFIG_FIH_SUSPEND_HANG_TIMER
	pr_info("early_suspend: add suspend_hang_timer\n");
	pid_suspend = (pid_t) current->pid;
	suspend_dump_counter = 0;
	suspend_hang_timer.data = EARLY_SUSPEND_HANG;
	mod_timer(&suspend_hang_timer, (jiffies + (POLLING_DUMP_SUSPEND_HANG_SECS*HZ)));
#endif
/*FIH-KERNEL-SC-Suspend_Hang_Timer-00+]*/

	mutex_lock(&early_suspend_lock);
	spin_lock_irqsave(&state_lock, irqflags);
	if (state == SUSPEND_REQUESTED)
		state |= SUSPENDED;
	else
		abort = 1;
	spin_unlock_irqrestore(&state_lock, irqflags);

	if (abort) {
		if (debug_mask & DEBUG_SUSPEND)
			pr_info("early_suspend: abort, state %d\n", state);
		mutex_unlock(&early_suspend_lock);
		goto abort;
	}

	if (debug_mask & DEBUG_SUSPEND)
		pr_info("early_suspend: call handlers\n");
	list_for_each_entry(pos, &early_suspend_handlers, link) {
/*KERNEL-SC-SUSPEND_RESUME_WAKELOCK_LOG-01+[ */
#ifdef CONFIG_FIH_SUSPEND_RESUME_LOG
		if (pos->suspend != NULL) {
				calltime = ktime_get();
				
				pos->suspend(pos);
				
				rettime = ktime_get();
				delta = ktime_sub(rettime, calltime);
				duration = (unsigned long long) ktime_to_us(delta);/*CORE-SC-suspend-resume-debug-msg-00**/
				pr_info("[PM]early_suspend: %pf takes %Ld usecs\n", pos->suspend, duration);/*CORE-SC-suspend-resume-debug-msg-00**/
			}
#else
		if (pos->suspend != NULL) {
			if (debug_mask & DEBUG_VERBOSE)
				pr_info("early_suspend: calling %pf\n", pos->suspend);
			pos->suspend(pos);
		}
#endif
/*KERNEL-SC-SUSPEND_RESUME_WAKELOCK_LOG-01+] */
	}
	mutex_unlock(&early_suspend_lock);
	
/*KERNEL-SC-SUSPEND_RESUME_WAKELOCK_LOG-01+[ */
	#ifdef CONFIG_FIH_SUSPEND_RESUME_LOG
		calltime = ktime_get();
		
		suspend_sys_sync_queue();
		
		rettime = ktime_get();
		delta = ktime_sub(rettime, calltime);
		duration = (unsigned long long) ktime_to_ns(delta) >> 10;
		pr_info("[PM]early suspend sync: takes %Ld usecs\n", duration);
	#else
		suspend_sys_sync_queue();
	#endif
/*KERNEL-SC-SUSPEND_RESUME_WAKELOCK_LOG-01+] */
	
abort:
	spin_lock_irqsave(&state_lock, irqflags);
	if (state == SUSPEND_REQUESTED_AND_SUSPENDED)
		wake_unlock(&main_wake_lock);
	spin_unlock_irqrestore(&state_lock, irqflags);

 
/*FIH-KERNEL-SC-Suspend_Hang_Timer-00+[*/
#ifdef CONFIG_FIH_SUSPEND_HANG_TIMER
	pr_info("early_suspend: del suspend_hang_timer\n");
	del_timer(&suspend_hang_timer);
#endif
/*FIH-KERNEL-SC-Suspend_Hang_Timer-00+]*/

}

static void late_resume(struct work_struct *work)
{
	struct early_suspend *pos;
	unsigned long irqflags;
	int abort = 0;
/*KERNEL-SC-SUSPEND_RESUME_WAKELOCK_LOG-01+[ */
#ifdef CONFIG_FIH_SUSPEND_RESUME_LOG
    ktime_t calltime, delta, rettime;
    unsigned long long duration = 0;/*CORE-SC-suspend-resume-debug-msg-00**/
	unsigned long long total_duration = 0;/*CORE-SC-suspend-resume-debug-msg-00**/
#endif
/*KERNEL-SC-SUSPEND_RESUME_WAKELOCK_LOG-01+] */

/*FIH-KERNEL-SC-Suspend_Hang_Timer-00+[*/
#ifdef CONFIG_FIH_SUSPEND_HANG_TIMER
	pr_info("late_resume: add suspend_hang_timer\n");
	pid_suspend = (pid_t) current->pid;
	suspend_dump_counter = 0;
	suspend_hang_timer.data = LATE_RESUME_HANG;
	mod_timer(&suspend_hang_timer, (jiffies + (POLLING_DUMP_SUSPEND_HANG_SECS*HZ)));
#endif
/*FIH-KERNEL-SC-Suspend_Hang_Timer-00+]*/

	mutex_lock(&early_suspend_lock);
	spin_lock_irqsave(&state_lock, irqflags);
	if (state == SUSPENDED)
		state &= ~SUSPENDED;
	else
		abort = 1;
	spin_unlock_irqrestore(&state_lock, irqflags);

	if (abort) {
		if (debug_mask & DEBUG_SUSPEND)
			pr_info("late_resume: abort, state %d\n", state);
		goto abort;
	}
	if (debug_mask & DEBUG_SUSPEND)
		pr_info("late_resume: call handlers\n");
	list_for_each_entry_reverse(pos, &early_suspend_handlers, link) {
/*KERNEL-SC-SUSPEND_RESUME_WAKELOCK_LOG-01+[ */
#ifdef CONFIG_FIH_SUSPEND_RESUME_LOG
		if (pos->resume != NULL) {
			calltime = ktime_get();
			
			pos->resume(pos);
			
			rettime = ktime_get();
			delta = ktime_sub(rettime, calltime);
			duration = (unsigned long long) ktime_to_us(delta);/*CORE-SC-suspend-resume-debug-msg-00**/
			pr_info("[PM]late_resume: %pf takes %Ld usecs\n", pos->resume, duration);/*CORE-SC-suspend-resume-debug-msg-00**/
			total_duration += duration;/*CORE-SC-suspend-resume-debug-msg-00**/
		}
#else
		if (pos->resume != NULL) {
			if (debug_mask & DEBUG_VERBOSE)
				pr_info("late_resume: calling %pf\n", pos->resume);

			pos->resume(pos);
		}
#endif
/*KERNEL-SC-SUSPEND_RESUME_WAKELOCK_LOG-01+] */	
	}
	/*CORE-SC-suspend-resume-debug-msg-00*[*/
	#ifdef CONFIG_FIH_SUSPEND_RESUME_LOG
		pr_info("late_resume: done after %Ld usecs\n", total_duration);
	#else
	if (debug_mask & DEBUG_SUSPEND)
		pr_info("late_resume: done\n");
	#endif
	/*CORE-SC-suspend-resume-debug-msg-00*]*/
abort:
	mutex_unlock(&early_suspend_lock);

	
/*FIH-KERNEL-SC-Suspend_Hang_Timer-00+[*/
#ifdef CONFIG_FIH_SUSPEND_HANG_TIMER
	pr_info("late_resume: del suspend_hang_timer\n");
	del_timer(&suspend_hang_timer);
#endif
/*FIH-KERNEL-SC-Suspend_Hang_Timer-00+]*/
}

void request_suspend_state(suspend_state_t new_state)
{
	unsigned long irqflags;
	int old_sleep;

	spin_lock_irqsave(&state_lock, irqflags);
	old_sleep = state & SUSPEND_REQUESTED;
	if (debug_mask & DEBUG_USER_STATE) {
		struct timespec ts;
		struct rtc_time tm;
		getnstimeofday(&ts);
		rtc_time_to_tm(ts.tv_sec, &tm);
		pr_info("request_suspend_state: %s (%d->%d) at %lld "
			"(%d-%02d-%02d %02d:%02d:%02d.%09lu UTC)\n",
			new_state != PM_SUSPEND_ON ? "sleep" : "wakeup",
			requested_suspend_state, new_state,
			ktime_to_ns(ktime_get()),
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec);
	}
	if (!old_sleep && new_state != PM_SUSPEND_ON) {
		state |= SUSPEND_REQUESTED;
		queue_work(suspend_work_queue, &early_suspend_work);
	} else if (old_sleep && new_state == PM_SUSPEND_ON) {
		state &= ~SUSPEND_REQUESTED;
		wake_lock(&main_wake_lock);
		queue_work(suspend_work_queue, &late_resume_work);
	}
	requested_suspend_state = new_state;
	spin_unlock_irqrestore(&state_lock, irqflags);
}

suspend_state_t get_suspend_state(void)
{
	return requested_suspend_state;
}
