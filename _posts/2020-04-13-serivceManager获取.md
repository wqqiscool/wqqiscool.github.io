---
layout:     post
title:     Binder通信“管家”
subtitle:    servicemanager之被使用
date:       2020-04-13
author:     wqq
header-img: img/post-bg-ios9-web.jpg
catalog: true
tags:
    - android
    - 驱动
    - native
    - Binder 
    - framework
    - ipc通信
---
#### 前情回顾
[上篇文章讲述了smr的启动过程，完成了三件事](https://wqqiscool.github.io/2020/04/10/Binder%E7%AE%A1%E5%AE%B6%E4%B9%8Bservicemanager/)
+ 打开驱动，mmap
+ 成文binder管家，成为守护进程
+ 开启looper循环

#### 概述
smr启动后就一直在循环当中了，不断的接受外部service和外部client的驱使，此时的smr充当的是binder通信过程中的service，外部service和client 都是作为client 角色的额主要目录源码文件：[frameworks/native/libs/binder](https://android.googlesource.com/platform/frameworks/native/+/refs/tags/android-8.0.0_r45/libs/binder/) 和[framework/av/media/meadiaservice/](https://android.googlesource.com/platform/frameworks/av/+/refs/tags/android-8.0.0_r45/media/mediaserver/main_mediaserver.cpp)和[frameworks/native/libs/binder/include/binder](https://android.googlesource.com/platform/frameworks/native/+/refs/tags/android-8.0.0_r45/libs/binder/include/binder)
+ Binder.cpp
+ Bpbinder.cpp
+ IInteface.cpp
+ IPCThread.cpp
+ ProcessState.cpp
+ Parcel.cpp
+ IserviceManager.cpp
+ ...
+ main_mediaservice.cpp
+ ...
+ IInterface.h
+ Binder.h
+ ...
#### 注册服务
注册的主语是为“client”提供服务的服务，但是注册这个过程其本身反而充当“client”的角色。

##### mediaservice入口main方法
smr这个服务是所有client可以主动知晓其handle-0的服务，作为一个服务要想被其他client提供服务，首先自己在smr中“注册”自己的服务，而本身“注册”这个动作也是ipc通信，因此需要有一个中枢神经来提供对接，就是smr。
本文以**mediaservice**作为入口，看其是如何注册到smg中去的

	int main(int argc __unused, char **argv __unused)
{
    signal(SIGPIPE, SIG_IGN);
    sp<ProcessState> proc(ProcessState::self());
    sp<IServiceManager> sm(defaultServiceManager());
    ALOGI("ServiceManager: %p", sm.get());
    InitializeIcuOrDie();
    MediaPlayerService::instantiate();
    ResourceManagerService::instantiate();
    registerExtensions();
    ProcessState::self()->startThreadPool();
    IPCThreadState::self()->joinThreadPool();
	}

这竟然是这个服务的‘全部代码’。出现了`sp`这个类型，模板类，[关于sp这种东西的学习]() 。
###### ProcessState::self()--获取ProcessState
+ framwork/native/libs/binder/ProcessState.cpp

	sp<ProcessState> ProcessState::self()
{
    Mutex::Autolock _l(gProcessMutex);
    if (gProcess != NULL) {
        return gProcess;
    }
    gProcess = new ProcessState("/dev/binder");
    return gProcess;
	}


采用了单例模式，若是非NULL直接返回，若是NULL（第一次）则调用其构造函数:

	ProcessState::ProcessState(const char *driver)
    : mDriverName(String8(driver))
    , mDriverFD(open_driver(driver))//此处 打开驱动，所以说每个应用服务唯一的一次打开驱动的时机
    , mVMStart(MAP_FAILED)
    , mThreadCountLock(PTHREAD_MUTEX_INITIALIZER)
    , mThreadCountDecrement(PTHREAD_COND_INITIALIZER)
    , mExecutingThreadsCount(0)
    , mMaxThreads(DEFAULT_MAX_BINDER_THREADS)
    , mStarvationStartTimeMs(0)
    , mManagesContexts(false)
    , mBinderContextCheckFunc(NULL)
    , mBinderContextUserData(NULL)
    , mThreadPoolStarted(false)
    , mThreadPoolSeq(1)
{
    if (mDriverFD >= 0) {
        // mmap the binder, providing a chunk of virtual address space to receive transactions.
        mVMStart = mmap(0, BINDER_VM_SIZE, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, mDriverFD, 0);
        if (mVMStart == MAP_FAILED) {
            // *sigh*
            ALOGE("Using /dev/binder failed: unable to mmap transaction memory.\n");
            close(mDriverFD);
            mDriverFD = -1;
            mDriverName.clear();
        }
    }
    LOG_ALWAYS_FATAL_IF(mDriverFD < 0, "Binder driver could not be opened.  Terminating.");
	}


###### defaultServiceManager()之获取servicemanager服务
[frameworks/native/binder/IserviceManager.cpp](https://android.googlesource.com/platform/frameworks/native/+/refs/tags/android-8.0.0_r45/libs/binder/IServiceManager.cpp)

	sp<IServiceManager> defaultServiceManager()
{
    if (gDefaultServiceManager != NULL) return gDefaultServiceManager;
    {
        AutoMutex _l(gDefaultServiceManagerLock);
        while (gDefaultServiceManager == NULL) {
            gDefaultServiceManager = interface_cast<IServiceManager>(
                ProcessState::self()->getContextObject(NULL));
            if (gDefaultServiceManager == NULL)
                sleep(1);
        }
    }
    return gDefaultServiceManager;
	}



先看下`interface_cast`参数`ProcessState::self()->getContextObject(NULL)`，又回到了上面的`processState.cpp`中的方法去了

	sp<IBinder> ProcessState::getContextObject(const sp<IBinder>& /*caller*/)
{
    return getStrongProxyForHandle(0);
	}

接着直接进入了`getStrongProxyForHandle(0)`这个0不就是smr的handle号吗，

	sp<IBinder> ProcessState::getStrongProxyForHandle(int32_t handle)
{
    sp<IBinder> result;
    AutoMutex _l(mLock);
    handle_entry* e = lookupHandleLocked(handle);
    if (e != NULL) {
        // We need to create a new BpBinder if there isn't currently one, OR we
        // are unable to acquire a weak reference on this current one.  See comment
        // in getWeakProxyForHandle() for more info about this.
        IBinder* b = e->binder;
        if (b == NULL || !e->refs->attemptIncWeak(this)) {
            if (handle == 0) {
                // Special case for context manager...
                // The context manager is the only object for which we create
                // a BpBinder proxy without already holding a reference.
                // Perform a dummy transaction to ensure the context manager
                // is registered before we create the first local reference
                // to it (which will occur when creating the BpBinder).
                // If a local reference is created for the BpBinder when the
                // context manager is not present, the driver will fail to
                // provide a reference to the context manager, but the
                // driver API does not return status.
                //
                // Note that this is not race-free if the context manager
                // dies while this code runs.
                //
                // TODO: add a driver API to wait for context manager, or
                // stop special casing handle 0 for context manager and add
                // a driver API to get a handle to the context manager with
                // proper reference counting.
                Parcel data;
                status_t status = IPCThreadState::self()->transact(
                        0, IBinder::PING_TRANSACTION, data, NULL, 0);
                if (status == DEAD_OBJECT)
                   return NULL;
            }
            b = new BpBinder(handle); 
            e->binder = b;
            if (b) e->refs = b->getWeakRefs();
            result = b;
        } else {
            // This little bit of nastyness is to allow us to add a primary
            // reference to the remote proxy when this team doesn't have one
            // but another team is sending the handle to us.
            result.force_set(b);
            e->refs->decWeak(this);
        }
    }
    return result;
	}


结构体：`handle_entry` 位于`ProcessState.h`

	struct handle_entry {
                IBinder* binder;
                RefBase::weakref_type* refs;
        };


查找是否拥有过？`lookupHandleLocked(handle)`

	ProcessState::handle_entry* ProcessState::lookupHandleLocked(int32_t handle)
{
    const size_t N=mHandleToObject.size();
    if (N <= (size_t)handle) {
        handle_entry e;
        e.binder = NULL;
        e.refs = NULL;
        status_t err = mHandleToObject.insertAt(e, N, handle+1-N);
        if (err < NO_ERROR) return NULL;
    }
    return &mHandleToObject.editItemAt(handle);
}

此时是空的vector，因此返回一个`Ibinder`为空的`handle_entry`，回到`getStrongProxyForHandle(int32_t handle)`,因为handle为0,会进行一个特殊的ping处理，接着往下走，走到`b = new BpBinder(handle)`，保留此记忆。

	BpBinder::BpBinder(int32_t handle)
    : mHandle(handle)
    , mAlive(1)
    , mObitsSent(0)
    , mObituaries(NULL)
{
    ALOGV("Creating BpBinder %p handle %d\n", this, mHandle);
    extendObjectLifetime(OBJECT_LIFETIME_WEAK);
    IPCThreadState::self()->incWeakHandle(handle);
	}	
	
也是单例模式，如果非NULL，直接返回，否则调用`interface_cast<IServiceManager>(ProcessState::self()->getContextObject(NULL));`,注意`interface_cast`,也是个模板方法，位于[frameworks/base/include/binder/IInteface.h](https://android.googlesource.com/platform/frameworks/base/+/e8331bd2e7ad3d62140143cafba3ff69be028557/include/binder/IInterface.h)

	
	te<typename INTERFACE>
inline sp<INTERFACE> interface_cast(const sp<IBinder>& obj)
{
    return INTERFACE::asInterface(obj);
	}

因此接着上句`gDefaultServiceManager = interface_cast<IServiceManager>(ProcessState::self()->getContextObject(NULL));`可以转化成`gDefaultServiceManager=IServiceManager.asInterface(ProcessState::self()->getContextObject(NULL))`,我们发现在`IserviceManager.cpp`和`IserviceManager.h`中并未直接的声明此方法，but，定睛一看在`IserviceManager.h`中却间接的声明了如下一段诡异的代码` DECLARE_META_INTERFACE(ServiceManager);`一个宏定义会不会就是上述的方法捏，我们进入到`IInterface.h`果然发现了此声明

	#define DECLARE_META_INTERFACE(INTERFACE)                               \\
    static const android::String16 descriptor;                          \\
    static android::sp<I##INTERFACE> asInterface(                       \\
            const android::sp<android::IBinder>& obj);                  \\
    virtual const android::String16& getInterfaceDescriptor() const;    \\
    I##INTERFACE();                                                     \\
    virtual ~I##INTERFACE();

这也是个模板类啊，到这时候不的不佩服这写法，此时就有了，很明显这就是一个通用的公共接口，但是在`IServiceManager.cpp`中仍未发现我们需要的这个`asInterface`方法，但是在结尾又出现了一句定义`IMPLEMENT_META_INTERFACE(ServiceManager, "android.os.IServiceManager");`,我们再次进入`IInterface.h`看下

	#define IMPLEMENT_META_INTERFACE(INTERFACE, NAME)                       \
    const android::String16 I##INTERFACE::descriptor(NAME);             \
    const android::String16&                                            \
            I##INTERFACE::getInterfaceDescriptor() const {              \
        return I##INTERFACE::descriptor;                                \
    }                                                                   \
    android::sp<I##INTERFACE> I##INTERFACE::asInterface(                \
            const android::sp<android::IBinder>& obj)                   \
    {                                                                   \
        android::sp<I##INTERFACE> intr;                                 \
        if (obj != NULL) {                                              \
            intr = static_cast<I##INTERFACE*>(                          \
                obj->queryLocalInterface(                               \
                        I##INTERFACE::descriptor).get());               \
            if (intr == NULL) {                                         \
                intr = new Bp##INTERFACE(obj);                          \
            }                                                           \
        }                                                               \
        return intr;                                                    \
    }                                                                   \
    I##INTERFACE::I##INTERFACE() { }                                    \
    I##INTERFACE::~I##INTERFACE() { }                                   \


皇天不服有心人，这代码写的好棒（绕），可以转化成new Bpbinder(0)->queryLoacalInterface("android.os.IServiceManager").get,返回null进入到下一步，返回BpServiceManager(new BpBinder(0));

#### 使用服务


