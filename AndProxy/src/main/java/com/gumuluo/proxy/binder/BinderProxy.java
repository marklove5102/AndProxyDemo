package com.gumuluo.proxy.binder;

import android.os.Parcel;

public class BinderProxy {
    static {
        System.loadLibrary("proxy");
    }

    public static void init() {
        nativeInit();
    }

    private static native void nativeInit();
}
