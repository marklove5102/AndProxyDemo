package com.gumuluo.proxy;

public class HookResponse {
    private long nativePtr;  // 指向 C 的 hook_response_t

    // 仅供 native 代码调用
    private HookResponse(long ptr) {
        this.nativePtr = ptr;
    }

    public native void setAction(int action);   // 使用 SvcInterceptor.ACTION_XXX
    public native void setError(int error);     // 例如 EPERM
    public native void setVal(long val);        // 修改返回值时使用
}
