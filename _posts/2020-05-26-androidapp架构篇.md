---
layout:     post
title:     架构篇
subtitle:  设计模式
date:       2020-05-28
author:     wqq
header-img: img/post-bg-ios9-web.jpg
catalog: true
tags:
    - android
    - 架构
    - 设计模式
    - MVP
    - 耦合
    - mvc
---

##### 架构原则
根据[Google官方文档](https://developer.android.com/jetpack/docs/guide?hl=zh-cn)有两大原则：
+ 分离关注点（Separation of concerns）
  + 把处理交互逻辑的代码不要全部集中于`Activity`、`Fragment`之中，减少对它们的依赖关系
+ 模型驱动界面（Drive UI from a model）
  + 依赖于数据存储模型，减少对生命周期的依赖，最好是持久性的数据存储模型。

理解观察者模式：谁是观察者，谁是被观察者，观察的是啥子
显然观察的是`activity`或者`Frament`的生命周期改变，被观察的当然就是‘activity’或者`fragment`，观察着当然是`p`或者`vm`了。

##### 架构模式
+ mvc (model, view ,controler)
+ mvp（model,view,Prensenter)
+ mvvm (model,view, modelview)

`mvc`适合一些比较简单的业务开发。`mvp`和`mvvp`适合业务复杂的开发，相较于`mvc`，分离开了了大量逻辑操作在`activity`和`Fragment`之中，解决了动辄几万行的逻辑操作在其中；另外能够跟踪生命周期，避免不必要的内存泄漏，`mvp`需要手动大量实现各种`presenter`来处理逻辑操作，其中很多的重复代码，于是`mvvp`应运而生，解决了我们这些板砖工的大量工作，就安心的去细化重要的部分喽。

##### 用到的设计模式
+ Lifecycle 观察者模式
+ LiveData  观察者模式
+ ViewModal 抽象工厂模式

##### 架构组件
google推荐的有 `ViewModel`、`LiveData（ MutableLiveData ，MediatorLiveData）`，``、`lifecycle`

随着androidX包的横空出世用来代替之前的`Android.support..`，上述类包都跟随更新，google建议开发者采用新的`AndoridX`包，之前的`ANdroid.support`包不再支持更新，停留在了`API28`版本。

##### mvvm 分析
由于两个版本还是有差异的，有些类或者方法都放弃了。但是我们还是对照分析一下：

1）`support`版本
`Livedata` 
