package com.gumuluo.proxy;

public class HookRequest {
    private long nativePtr;  // 指向 C 的 hook_request_t

    // 仅供 native 代码调用
    private HookRequest(long ptr) {
        this.nativePtr = ptr;
    }

    public native int getSyscallNr();
    public native int getPid();
    public native long getArg(int index);      // index 0~5
    public native long getRegX(int index);     // index 0~30
    public native long getSp();
    public native long getPc();
    public native long getPstate();

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("HookRequest{syscall=").append(getSyscallNr())
                .append(", pid=").append(getPid())
                .append(", args=[");
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(",");
            sb.append(getArg(i));
        }
        sb.append("]}");
        return sb.toString();
    }
}
