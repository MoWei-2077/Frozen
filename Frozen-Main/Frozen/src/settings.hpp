#pragma once

#include "utils.hpp"
#include "freezeit.hpp"

class Settings {
private:
    Freezeit& freezeit;
    mutex writeSettingMutex;
    const char* settingsPath = "/data/adb/modules/Frozen/settings.db";
    const static size_t SETTINGS_SIZE = 256;
    uint8_t settingsVar[SETTINGS_SIZE] = {
            8,  //[0] 设置文件版本
            0,  //[1] 
            10, //[2] freezeTimeout sec
            4,  //[3] wakeupTimeoutIdx  定时唤醒 参数索引 0-5：关闭, 5m, 15m, 30m, 1h, 2h
            20, //[4] terminateTimeout sec
            0,  //[5] setMode 设置Freezer模式  0: 全局SIGSTOP, 1: V1Frozen, 2:V2 UID 3:V2 Frozen 4:Auto
            2,  //[6] refreezeTimeoutIdx 定时压制 参数索引 0-3：关闭, 30m, 1h, 2h
            0,  //[7]
            0,  //[8]
            0,  //[9]
            1,  //[10] 
            0,  //[11]
            0,  //[12]
            1,  //[13] 电池监控
            0,  //[14] 电流校准
            0,  //[15] 双电芯
            1,  //[16] 调整 lmk 参数 仅安卓12-15
            1,  //[17] 深度Doze
            0,  //[18] 扩展前台
            0,  //[19] 内存回收
            0,  //[20] Binder冻结
            0,  //[21] 开机冻结
            1,  //[23] 全局断网
            0,  //[24] 清理电池优化白名单
            0,  //[25] ReKernel临时解冻
            0,  //[26] 备用前台识别
            0,  //[27] 极简模式
            0,  //[30] 详细日志
            0,  //[31]
            0,  //[32]
    };


    // 关闭, 30m, 1h, 2h
    static constexpr int refreezeTimeoutList[] = { 86400 * 365, 60 * 30, 3600, 3600 * 2 };
    // 最大索引
    static constexpr int refreezeTimeoutIdxMax = sizeof(refreezeTimeoutList) / sizeof(refreezeTimeoutList[0]) - 1;

    // 关闭, 5m, 15m, 30m, 1h, 2h
    static constexpr int wakeupTimeoutList[] = { 86400 * 365, 60 * 5, 60 * 15, 60 * 30, 3600, 3600 * 2 };
    // 最大索引
    static constexpr int wakeupTimeoutIdxMax = sizeof(wakeupTimeoutList) / sizeof(wakeupTimeoutList[0]) - 1;


public:
    uint8_t& settingsVer = settingsVar[0];          // 设置文件版本
    //uint8_t& unknown = settingsVar[1];          // 
    uint8_t& freezeTimeout = settingsVar[2];        // 超时冻结 单位 秒
    uint8_t& wakeupTimeoutMin = settingsVar[3];     // 定时唤醒 单位 分
    uint8_t& terminateTimeout = settingsVar[4];     // 超时杀死 单位 秒
    uint8_t& setMode = settingsVar[5];              // Freezer模式
    uint8_t& refreezeTimeoutIdx = settingsVar[6];   // 定时压制 参数索引 0-4, 15m, 30m, 1h, 2h

    uint8_t& enableBatteryMonitor = settingsVar[13];   // 电池监控
    uint8_t& enableCurrentFix = settingsVar[14];       // 电池电流校准
    uint8_t& enableDoubleCell = settingsVar[15];       // 双电芯 电流翻倍
    uint8_t& enableLMK = settingsVar[16];              // 调整 lmk 参数 仅安卓11-15
    uint8_t& enableDoze = settingsVar[17];             // 深度Doze
    uint8_t& enableWindows = settingsVar[18];          // 扩展前台
    uint8_t& enableMemoryRecycle = settingsVar[19];   // 内存回收
    uint8_t& enableBinderFreeze = settingsVar[20];     // Binder冻结
    uint8_t& enableBreakNetwork = settingsVar[23];   // 全局断网
    uint8_t& enableClearBatteryList = settingsVar[24]; // 清理电池优化白名单
    uint8_t& enableReKernel = settingsVar[25]; // ReKernel临时解冻
    uint8_t& enableBackupTopAPPrecognition = settingsVar[26]; // 备用前台识别
    uint8_t& enableEzMode = settingsVar[27]; // 极简模式
    uint8_t& enableDebug = settingsVar[30];        // 调试日志

    Settings& operator=(Settings&&) = delete;

    Settings(Freezeit& freezeit) : freezeit(freezeit) {

        freezeit.setDebugPtr(settingsVar+30);

        auto fd = open(settingsPath, O_RDONLY);
        if (fd > 0) {
            uint8_t tmp[SETTINGS_SIZE] = { 0 };
            int readSize = read(fd, tmp, SETTINGS_SIZE);
            close(fd);

            if (readSize != SETTINGS_SIZE) {
                freezeit.log("设置文件校验失败, 将使用默认设置参数, 并更新设置文件");
                freezeit.logFmt("读取大小: %d Bytes.  要求大小: 256 Bytes.", readSize);
                freezeit.log(save() ? "⚙️设置成功" : "🔧设置文件写入失败");
            }
            else if (tmp[0] != settingsVer) {
                freezeit.logFmt("设置文件当前版本: V%d 要求版本: V%d，版本不兼容, 将使用新版默认设置参数, 请根据情况自行重新调整设置", 
                    static_cast<int>(tmp[0]), static_cast<int>(settingsVer));
                freezeit.log(save() ? "⚙️设置成功" : "🔧设置文件写入失败");
            }
            else {
                memcpy(settingsVar, tmp, SETTINGS_SIZE);

                bool isError = false;
                if (setMode > 3) {
                    isError = true;
                    setMode = 0;
                    freezeit.logFmt("冻结模式参数[%d]错误, 已重设为 全局SIGSTOP", (int)setMode);
                }
                             /*  if (refreezeTimeoutIdx > 4) {
                    freezeit.logFmt("定时压制参数[%d]错误, 已重设为 30分钟", static_cast<int>(refreezeTimeoutIdx));
                    refreezeTimeoutIdx = 2;
                    isError = true;
                }
                */
                if (wakeupTimeoutMin < 3 || wakeupTimeoutMin > 120) {
                    freezeit.logFmt("定时解冻参数[%d]错误, 已重置为30分", (int)wakeupTimeoutMin);
                    wakeupTimeoutMin = 30;
                    isError = true;
                }
                if (freezeTimeout < 1 || 60 < freezeTimeout) {
                    isError = true;
                    freezeTimeout = 3;
                    freezeit.logFmt("超时冻结参数[%d]错误, 已重置为 %d 秒",
                        static_cast<int>(freezeTimeout), (int)freezeTimeout);
                }
                if (terminateTimeout < 3 || 120 < terminateTimeout) {
                    isError = true;
                    terminateTimeout = 30;
                    freezeit.logFmt("超时杀死参数[%d]错误, 已重置为 %d 秒",
                        static_cast<int>(terminateTimeout), (int)terminateTimeout);
                }
                if (isError) {
                    freezeit.log("新版本可能会调整部分设置，可能需要重新设置");
                    freezeit.log(save() ? "⚙️设置成功" : "🔧设置文件写入失败");
                }
            }
            if (freezeit.isOppoVivo) {
                freezeit.log("开启扩展识别 OPPO/VIVO/IQOO/REALME");
                enableWindows = true;
            }
        }
        else { 
            freezeit.log("设置文件不存在, 将初始化设置文件");
            freezeit.log(save() ? "⚙️设置成功" : "🔧设置文件写入失败");
        }
    }

    uint8_t& operator[](const int key) {
        return settingsVar[key];
    }

    const char* get() {
        return (const char*)settingsVar;
    }

    size_t size() {
        return SETTINGS_SIZE;
    }

    bool isRefreezeEnable() const {
        return 0 < refreezeTimeoutIdx && refreezeTimeoutIdx <= refreezeTimeoutIdxMax;
    }
    int getRefreezeTimeout() const {
        return refreezeTimeoutList[refreezeTimeoutIdx <= refreezeTimeoutIdxMax ? refreezeTimeoutIdx : 0];
    }

    bool save() {
        lock_guard<mutex> lock(writeSettingMutex);
        auto fd = open(settingsPath, O_WRONLY | O_TRUNC | O_CREAT, 0666);
        if (fd > 0) {
            int writeSize = write(fd, settingsVar, SETTINGS_SIZE);
            close(fd);
            if (writeSize == SETTINGS_SIZE)
                return true;

            freezeit.logFmt("设置异常, 文件实际写入[%d]Bytes", writeSize);
        }
        return false;
    }

    int checkAndSet(const int idx, const int val, char* replyBuf) {
        const size_t REPLY_BUF_SIZE = 2048;

        switch (idx) {
        case 2: { // freezeTimeout sec
            if (val < 1 || 60 < val)
                return snprintf(replyBuf, REPLY_BUF_SIZE, "超时冻结参数错误, 欲设为:%d", val);
        }
              break;

        case 3: {  // wakeupTimeoutIdx
            if (val < 3 || 120 < val)
                return snprintf(replyBuf, REPLY_BUF_SIZE, "定时解冻参数错误, 正常范围:3~120, 欲设为:%d", val);
        }
              break;

        case 4: { // wakeupTimeoutIdx sec
            if (val < 3 || 120 < val)
                return snprintf(replyBuf, REPLY_BUF_SIZE, "超时杀死参数错误, 欲设为:%d", val);
        }
              break;

        case 5: { // setMode 0-1-2-3-4
            if (val > 5)
                return snprintf(replyBuf, REPLY_BUF_SIZE, "冻结模式参数错误, 欲设为:%d", val);
        }
              break;

        case 6: { // refreezeTimeoutIdx
            if (val > refreezeTimeoutIdxMax)
                return snprintf(replyBuf, REPLY_BUF_SIZE, "定时压制参数错误, 欲设为:%d", val);
        }
              break;

        case 10: // xxx
        case 11: // xxx
        case 12: // xxx
        case 13: // 电池监控
        case 14: // 电流校准
        case 15: // 双电芯
        case 16: // lmk
        case 17: // doze
        case 18: // xxx
        case 19: //
        case 20: // Binder冻结
        case 23: // 全局断网
        case 24: // 清理电池白名单
        case 25: // ReKernel临时解冻
        case 26: // 备用前台识别
        case 27: // 极简模式
        case 30: // 详细日志
        {
            if (val != 0 && val != 1)
                return snprintf(replyBuf, REPLY_BUF_SIZE, "开关值错误, 正常范围:0/1, 欲设为:%d", val);
        }
        break;

        default: {
            freezeit.logFmt("🔧设置失败，设置项不存在, [%d]:[%d]", idx, val);
            return snprintf(replyBuf, REPLY_BUF_SIZE, "设置项不存在, [%d]:[%d]", idx, val);
        }
        }

        settingsVar[idx] = val;
        if (save()) {
            return snprintf(replyBuf, REPLY_BUF_SIZE, "success");
        }
        else {
            freezeit.logFmt("🔧设置失败，写入设置文件失败, [%d]:%d", idx, val);
            return snprintf(replyBuf, REPLY_BUF_SIZE, "写入设置文件失败, [%d]:%d", idx, val);
        }
    }
};
