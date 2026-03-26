package com.gumuluo.proxy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Process;
import android.util.Log;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

@RunWith(AndroidJUnit4.class)
public class SvcInterceptorTest {

    private static final int SYS_GETPID = 172; // ARM64 getpid syscall number

    @Test
    public void testInterceptGetPid() throws Exception {
        int[] syscalls = new int[]{SYS_GETPID, -1};
        assertEquals(0, SvcInterceptor.init(syscalls));

        AtomicBoolean hookCalled = new AtomicBoolean(false);

        SvcInterceptor.registerHook(SYS_GETPID, new SvcInterceptor.Callback() {
            @Override
            public void onSyscall(HookRequest request, HookResponse response) {
                hookCalled.set(true);
                System.out.println("Hook triggered: pid=" + request.getPid() +
                        ", syscall=" + request.getSyscallNr());
                response.setAction(SvcInterceptor.ACTION_ALLOW);
            }
        });

        // 等待 supervisor 子进程启动完毕（可根据实际情况调整）
        Thread.sleep(200);

        int pid = getpid();
        assertTrue("getpid returned invalid pid", pid > 0);

        assertTrue("Hook was not called", hookCalled.get());

        SvcInterceptor.unregisterHook(SYS_GETPID);
    }

    @Test
    public void testDenySyscall() throws Exception {
        int[] syscalls = new int[]{SYS_GETPID, -1};
        assertEquals(0, SvcInterceptor.init(syscalls));

        SvcInterceptor.registerHook(SYS_GETPID, new SvcInterceptor.Callback() {
            @Override
            public void onSyscall(HookRequest request, HookResponse response) {
                response.setAction(SvcInterceptor.ACTION_DENY);
                response.setError(1); // EPERM
            }
        });

        Thread.sleep(200);

        int pid = getpid();
        assertEquals("Expected getpid to be denied and return -1", -1, pid);

        SvcInterceptor.unregisterHook(SYS_GETPID);
    }

    @Test
    public void testModifyReturnValue() throws Exception {
        int[] syscalls = new int[]{SYS_GETPID, -1};
        assertEquals(0, SvcInterceptor.init(syscalls));

        SvcInterceptor.registerHook(SYS_GETPID, new SvcInterceptor.Callback() {
            @Override
            public void onSyscall(HookRequest request, HookResponse response) {
                response.setAction(SvcInterceptor.ACTION_MODIFY);
                response.setVal(12345L);
            }
        });

        Thread.sleep(200);

        int pid = getpid();
        assertEquals("Return value should be modified to 12345", 12345, pid);

        SvcInterceptor.unregisterHook(SYS_GETPID);
    }

    public native int getpid();
}