//
// Created by lenovo on 2026/3/24.
//

#include "BinderHook.h"

extern "C" JNIEXPORT void JNICALL
Java_com_gumuluo_proxy_binder_BinderProxy_nativeInit(JNIEnv* env, jclass clazz) {
    JavaVM* vm;
    env->GetJavaVM(&vm);
    BinderHook::instance().init(vm);
}

// 外部符号：ioctl_proxy 由 hook 框架调用
int ioctl_proxy(int fd, unsigned long request, void* args) {
    return BinderHook::instance().process_ioctl(fd, request, args);
}

extern "C" JNIEXPORT void JNICALL
Java_com_gumuluo_proxy_binder_BinderDispatcher_nativeAddJavaCallback(JNIEnv* env, jclass clazz,
                                                                     jstring serviceName, jstring methodName,
                                                                     jboolean isBefore) {
    const char* svc = env->GetStringUTFChars(serviceName, nullptr);
    const char* mtd = env->GetStringUTFChars(methodName, nullptr);
    BinderHook::instance().addJavaCallback(svc, mtd, isBefore);
    env->ReleaseStringUTFChars(serviceName, svc);
    env->ReleaseStringUTFChars(methodName, mtd);
}

extern "C" JNIEXPORT void JNICALL
Java_com_gumuluo_proxy_binder_BinderDispatcher_nativeRemoveJavaCallback(JNIEnv* env, jclass clazz,
                                                                        jstring serviceName, jstring methodName,
                                                                        jboolean isBefore) {
    const char* svc = env->GetStringUTFChars(serviceName, nullptr);
    const char* mtd = env->GetStringUTFChars(methodName, nullptr);
    BinderHook::instance().removeJavaCallback(svc, mtd, isBefore);
    env->ReleaseStringUTFChars(serviceName, svc);
    env->ReleaseStringUTFChars(methodName, mtd);
}
