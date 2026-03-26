package com.gumuluo.proxy;

import android.app.ActivityManager;
import android.content.Context;
import android.util.Log;

import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.runner.AndroidJUnit4;

import com.gumuluo.proxy.binder.BinderDispatcher;
import com.gumuluo.proxy.binder.BinderProxy;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.lsposed.hiddenapibypass.HiddenApiBypass;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class BinderInterceptorTest {
    static private final String TAG = "BinderInterceptorTest";

    @Before
    public void setUp() {
        HiddenApiBypass.addHiddenApiExemptions("");
        BinderProxy.init();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x ", b & 0xff));
        }
        return sb.toString();
    }

    @Test
    public void testModifyGetMemoryInfo() {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        ActivityManager.MemoryInfo memoryInfo = new ActivityManager.MemoryInfo();
        am.getMemoryInfo(memoryInfo);
        Log.d(TAG, "before availMem = " + memoryInfo.availMem);

        // 注册 after 回调（修改返回结果）
        BinderDispatcher.registerAfter("android.app.IActivityManager", "getMemoryInfo",
                (data, outReply) -> {
                    Log.d(TAG, "After: getMemoryInfo");
                    try {
                        int originalSize = data.dataSize();
                        Log.d(TAG, "Original dataSize: " + originalSize);

                        // 将原始数据完整复制到 outReply
                        outReply.appendFrom(data, 0, originalSize);
                        // 定位到 availMem 字段（偏移8）
                        outReply.setDataPosition(8);
                        // 写入新值
                        outReply.writeLong(1024L * 1024 * 1024); // 1GB

                        Log.d(TAG, "Modified dataSize: " + outReply.dataSize());
                        return true;
                    } catch (Exception e) {
                        Log.e(TAG, "Failed to modify MemoryInfo", e);
                        return false;
                    }
                });

        // 再次调用，检查修改效果
        am.getMemoryInfo(memoryInfo);
        assertEquals(1024L * 1024 * 1024, memoryInfo.availMem);
    }
}