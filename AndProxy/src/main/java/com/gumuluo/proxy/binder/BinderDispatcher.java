package com.gumuluo.proxy.binder;

import android.os.Parcel;
import android.util.Log;

import java.util.HashMap;
import java.util.Map;

public class BinderDispatcher {
    private static final String TAG = "BinderDispatcher";

    // 映射 key = serviceName + "#" + methodName
    private static final Map<String, BinderInterceptor> beforeMap = new HashMap<>();
    private static final Map<String, BinderInterceptor> afterMap = new HashMap<>();

    // 注册 before 回调
    public static void registerBefore(String serviceName, String methodName, BinderInterceptor interceptor) {
        String key = serviceName + "#" + methodName;
        synchronized (beforeMap) {
            beforeMap.put(key, interceptor);
        }
        Log.d(TAG, "Registered before: " + key);
        nativeAddJavaCallback(serviceName, methodName, true);
    }

    // 注销 before 回调
    public static void unregisterBefore(String serviceName, String methodName) {
        String key = serviceName + "#" + methodName;
        synchronized (beforeMap) {
            beforeMap.remove(key);
        }
        Log.d(TAG, "Unregistered before: " + key);
        nativeRemoveJavaCallback(serviceName, methodName, true);
    }

    // 注册 after 回调
    public static void registerAfter(String serviceName, String methodName, BinderInterceptor interceptor) {
        String key = serviceName + "#" + methodName;
        synchronized (afterMap) {
            afterMap.put(key, interceptor);
        }
        Log.d(TAG, "Registered after: " + key);
        nativeAddJavaCallback(serviceName, methodName, false);
    }

    // 注销 after 回调
    public static void unregisterAfter(String serviceName, String methodName) {
        String key = serviceName + "#" + methodName;
        synchronized (afterMap) {
            afterMap.remove(key);
        }
        Log.d(TAG, "Unregistered after: " + key);
        nativeRemoveJavaCallback(serviceName, methodName, false);
    }

    // Native 同步方法
    private static native void nativeAddJavaCallback(String serviceName, String methodName, boolean isBefore);
    private static native void nativeRemoveJavaCallback(String serviceName, String methodName, boolean isBefore);

    // Native 调用：before 分发（供 Native 调用）
    static boolean dispatchBefore(String serviceName, String methodName, Parcel data, Parcel outReply) {
        String key = serviceName + "#" + methodName;
        BinderInterceptor interceptor;
        synchronized (beforeMap) {
            interceptor = beforeMap.get(key);
        }
        if (interceptor != null) {
            return interceptor.onTransaction(data, outReply);
        }
        return false;
    }

    // Native 调用：after 分发
    static boolean dispatchAfter(String serviceName, String methodName, Parcel data, Parcel outReply) {
        String key = serviceName + "#" + methodName;
        BinderInterceptor interceptor;
        synchronized (afterMap) {
            interceptor = afterMap.get(key);
        }
        if (interceptor != null) {
            return interceptor.onTransaction(data, outReply);
        }
        return false;
    }
}