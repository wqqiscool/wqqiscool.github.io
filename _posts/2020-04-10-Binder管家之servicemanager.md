---
layout:     post
title:     Binder通信“管家”
subtitle:    servicemanager之守护进程
date:       2020-04-10
author:     wqq
header-img: img/post-bg-ios9-web.jpg
catalog: true
tags:
    - android
    - 驱动
    - Linux
    - Binder
    - ipc通信
---
#### servicemanager概述
servicemanager是binder通信的大管家，提供**client**查询服务，提供**service**注册服务，同时也是binder的守护进程。位于[frameworks/native/cmds/serivcemanager](https://android.googlesource.com/platform/frameworks/native/+/refs/tags/android-8.0.0_r45/cmds/servicemanager/)
+ binder.c
+ binder.h
+ service_manager.c
+ ......

##### 启动
**ServiceManager**是由init进程通过解析**[init.rc]()**文件而创建的，其所对应的可执行程序**/system/bin/servicemanager**，所对应的源文件是**service_manager.c**，进程名为**/system/bin/servicemanager**。

	service servicemanager /system/bin/servicemanager
    	class core
    	user system
    	group system
    	critical
    	onrestart restart healthd
    	onrestart restart zygote
    	onrestart restart media
    	onrestart restart surfaceflinger
    	onrestart restart drm


解析完成进入`Service_manager.c`文件中的**main**方法中去，主要干了三件事
+ 打开binder驱动
+ 成为“管家”
+ 开启looper循环

code：

	int main(int argc, char** argv)
{
    struct binder_state *bs;
    union selinux_callback cb;
    char *driver;
    if (argc > 1) {
        driver = argv[1];
    } else {
        driver = "/dev/binder";
    }
    bs = binder_open(driver, 128*1024);
    if (!bs) {
#ifdef VENDORSERVICEMANAGER
        ALOGW("failed to open binder driver %s\n", driver);
        while (true) {
            sleep(UINT_MAX);
        }
#else
        ALOGE("failed to open binder driver %s\n", driver);
#endif
        return -1;
    }
    if (binder_become_context_manager(bs)) {
        ALOGE("cannot become context manager (%s)\n", strerror(errno));
        return -1;
    }
    cb.func_audit = audit_callback;
    selinux_set_callback(SELINUX_CB_AUDIT, cb);
    cb.func_log = selinux_log_callback;
    selinux_set_callback(SELINUX_CB_LOG, cb);
#ifdef VENDORSERVICEMANAGER
    sehandle = selinux_android_vendor_service_context_handle();
#else
    sehandle = selinux_android_service_context_handle();
#endif
    selinux_status_open(true);
    if (sehandle == NULL) {
        ALOGE("SELinux: Failed to acquire sehandle. Aborting.\n");
        abort();
    }
    if (getcon(&service_manager_context) != 0) {
        ALOGE("SELinux: Failed to acquire service_manager context. Aborting.\n");
        abort();
    }
    binder_loop(bs, svcmgr_handler);
    return 0;
	}


可以看到其中的三个重要方法`binder_open(driver,128*1024),binder_become_context_manager(bs),binder_looper(bs,svcmgr_handler)`,然后就分别进入了跟此文件同一个目录下的**binder.c**,当然再下一步就是进入了驱动层的**[binder.c](https://wqqiscool.github.io/2020/04/08/Binder%E9%A9%B1%E5%8A%A8%E5%B1%82%E6%8E%A2%E7%A9%B6/#binder_open)**分别对应的open，mmap，等等诸如方法

##### binder_open()
`bs=binder_open(driver,128*1024)`进入到[fram../cmds/serive../binder.c](https://android.googlesource.com/platform/frameworks/native/+/refs/tags/android-8.0.0_r45/cmds/servicemanager/binder.c) 


	struct binder_state
{
    int fd;
    void *mapped;
    size_t mapsize;
};
struct binder_state *binder_open(const char* driver, size_t mapsize)
{
    struct binder_state *bs;
    struct binder_version vers;
    bs = malloc(sizeof(*bs));
    if (!bs) {
        errno = ENOMEM;
        return NULL;
    }
    bs->fd = open(driver, O_RDWR | O_CLOEXEC);
    if (bs->fd < 0) {
        fprintf(stderr,"binder: cannot open %s (%s)\n",
                driver, strerror(errno));
        goto fail_open;
    }
    if ((ioctl(bs->fd, BINDER_VERSION, &vers) == -1) ||
        (vers.protocol_version != BINDER_CURRENT_PROTOCOL_VERSION)) {
        fprintf(stderr,
                "binder: kernel driver version (%d) differs from user space version (%d)\n",
                vers.protocol_version, BINDER_CURRENT_PROTOCOL_VERSION);
        goto fail_open;
    }
    bs->mapsize = mapsize;
    bs->mapped = mmap(NULL, mapsize, PROT_READ, MAP_PRIVATE, bs->fd, 0);
    if (bs->mapped == MAP_FAILED) {
        fprintf(stderr,"binder: cannot map device (%s)\n",
                strerror(errno));
        goto fail_map;
    }
    return bs;
fail_map:
    close(bs->fd);
fail_open:
    free(bs);
    return NULL;
	}



	
	struct binder_state *binder_open(const char* driver, size_t mapsize)
{
    struct binder_state *bs;
    struct binder_version vers;
    bs = malloc(sizeof(*bs));
    if (!bs) {
        errno = ENOMEM;
        return NULL;
    }
    bs->fd = open(driver, O_RDWR | O_CLOEXEC);
    if (bs->fd < 0) {
        fprintf(stderr,"binder: cannot open %s (%s)\n",
                driver, strerror(errno));
        goto fail_open;
    }
    if ((ioctl(bs->fd, BINDER_VERSION, &vers) == -1) ||
        (vers.protocol_version != BINDER_CURRENT_PROTOCOL_VERSION)) {
        fprintf(stderr,
                "binder: kernel driver version (%d) differs from user space version (%d)\n",
                vers.protocol_version, BINDER_CURRENT_PROTOCOL_VERSION);
        goto fail_open;
    }
    bs->mapsize = mapsize;
    bs->mapped = mmap(NULL, mapsize, PROT_READ, MAP_PRIVATE, bs->fd, 0);
    if (bs->mapped == MAP_FAILED) {
        fprintf(stderr,"binder: cannot map device (%s)\n",
                strerror(errno));
        goto fail_map;
    }
    return bs;
fail_map:
    close(bs->fd);
fail_open:
    free(bs);
    return NULL;
	}


可以看到在从上层传入到open指令到这时，此时的open不仅仅open，还做了一件mmap（妈买皮）的事情：
+  bs->fd = open(driver, O_RDWR | O_CLOEXEC);
+  bs->mapped = mmap(NULL, mapsize, PROT_READ, MAP_PRIVATE, bs->fd, 0);

当然上篇文章讲到过。[回顾一下]https://wqqiscool.github.io/2020/04/08/Binder%E9%A9%B1%E5%8A%A8%E5%B1%82%E6%8E%A2%E7%A9%B6/#binder_open()
