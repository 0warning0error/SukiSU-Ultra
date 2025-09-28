#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/printk.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include "kernel_compat.h"
#include "manual_su.h"
#include "ksu.h"
#include "allowlist.h"
#include "manager.h"

static const char *ksu_su_password = "zakozako";
extern void escape_to_root_for_cmd_su(uid_t, pid_t);
#define PENDING_ROOT_FILE "/data/local/tmp/.pending_root"

int ksu_manual_su_escalate(uid_t target_uid, pid_t target_pid,
                           const char __user *user_password)
{
    if (ksu_is_current_verified())
        goto allowed;

    if (current_uid().val == 0 || is_manager() || ksu_is_allow_uid(current_uid().val))
        goto allowed;

    if (!user_password) {
        pr_warn("manual_su: password required\n");
        return -EACCES;
    }
    char buf[64];
    if (strncpy_from_user(buf, user_password, sizeof(buf) - 1) < 0)
        return -EFAULT;
    buf[sizeof(buf) - 1] = '\0';

    if (strcmp(buf, ksu_su_password) != 0) {
        pr_warn("manual_su: wrong password\n");
        return -EACCES;
    }

    ksu_mark_current_verified();

allowed:
    escape_to_root_for_cmd_su(target_uid, target_pid);
    return 0;
}

bool is_pending_root(uid_t uid)
{
    struct file *fp;
    char buf[16] = {0};
    int read_uid;
    bool found = false;
    loff_t pos = 0;

    fp = ksu_filp_open_compat(PENDING_ROOT_FILE, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        pr_info("pending_root: file not found\n");
        return false;
    }

    while (true) {
        ssize_t len = ksu_kernel_read_compat(fp, buf, sizeof(buf) - 1, &pos);
        if (len <= 0) break;

        buf[len] = '\0';

        char *line = buf;
        char *endl;
        while ((endl = strchr(line, '\n')) != NULL) {
            *endl = '\0';
            if (kstrtoint(line, 10, &read_uid) == 0 && read_uid == uid) {
                found = true;
                goto out;
            }
            line = endl + 1;
        }

        if (strlen(line) > 0) {
            if (kstrtoint(line, 10, &read_uid) == 0 && read_uid == uid) {
                found = true;
                goto out;
            }
        }
    }

out:
    filp_close(fp, NULL);
    return found;
}


void remove_pending_root(uid_t uid)
{
    struct file *fp;
    char buf[16] = {0};
    int read_uid;
    loff_t pos = 0;
    char new_buf[256] = {0};
    int offset = 0;

    fp = ksu_filp_open_compat(PENDING_ROOT_FILE, O_RDONLY, 0);
    if (IS_ERR(fp)) return;

    while (true) {
        ssize_t len = ksu_kernel_read_compat(fp, buf, sizeof(buf) - 1, &pos);
        if (len <= 0) break;

        buf[len] = '\0';

        char *line = buf;
        char *endl;
        while ((endl = strchr(line, '\n')) != NULL) {
            *endl = '\0';
            if (kstrtoint(line, 10, &read_uid) == 0 && read_uid != uid) {
                int line_len = strlen(line);
                if (offset + line_len + 1 < sizeof(new_buf)) {
                    sprintf(new_buf + offset, "%s\n", line);
                    offset += line_len + 1;
                }
            }
            line = endl + 1;
        }

        if (strlen(line) > 0) {
            if (kstrtoint(line, 10, &read_uid) == 0 && read_uid != uid) {
                int line_len = strlen(line);
                if (offset + line_len + 1 < sizeof(new_buf)) {
                    sprintf(new_buf + offset, "%s\n", line);
                    offset += line_len + 1;
                }
            }
        }
    }

    filp_close(fp, NULL);

    fp = ksu_filp_open_compat(PENDING_ROOT_FILE, O_WRONLY | O_TRUNC, 0644);
    if (IS_ERR(fp)) return;

    pos = 0;
    if (offset > 0) {
        ksu_kernel_write_compat(fp, new_buf, offset, &pos);
    }
    filp_close(fp, NULL);
}