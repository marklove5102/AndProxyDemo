package com.gumuluo.proxy.binder;

import android.os.Parcel;

public interface BinderInterceptor {
    /**
     * 处理 Binder 事务
     * @param data     原始数据（可读）
     * @param outReply 输出数据（可写），若返回 true，将使用 outReply 替换原数据
     * @return true 表示数据已被修改，需替换；false 表示无需修改
     */
    boolean onTransaction(Parcel data, Parcel outReply);
}

