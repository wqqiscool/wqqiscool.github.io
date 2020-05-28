---
layout:     post
title:     架构篇
subtitle:  设计模式
date:       2020-04-07
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

##### 架构模式
+ mvc
+ mvp
+ mvvm

##### 架构组件
google推荐的有 `ViewModel`、`LiveData（ MutableLiveData ，MediatorLiveData）`，``、`lifecycle`



