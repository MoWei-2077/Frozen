#pragma once

#include "utils.hpp"
#include "vpopen.hpp"
#include "managedApp.hpp"
#include "doze.hpp"
#include "freezeit.hpp"
#include "systemTools.hpp"


#define PACKET_SIZE      128
#define NETLINK_UNIT_DEFAULT     -1 
#define USER_PORT        100
#define MAX_PLOAD        125
#define MSG_LEN          125

typedef struct _user_msg_info
{
    struct nlmsghdr hdr;
    char  msg[MSG_LEN];
} user_msg_info;

class Freezer {
private:
    Freezeit& freezeit;
    ManagedApp& managedApp;
    SystemTools& systemTools;
    Settings& settings;
    Doze& doze;

    vector<thread> threads;

    WORK_MODE workMode = WORK_MODE::GLOBAL_SIGSTOP;
    map<int, int> pendingHandleList;     //挂起列队 无论黑白名单 { uid, timeRemain:sec }
    set<int> lastForegroundApp;          //前台应用
    set<int> curForegroundApp;           //新前台应用
    set<int> curFgBackup;                //新前台应用备份 用于进入doze前备份， 退出后恢复
    set<int> naughtyApp;                 //冻结期间存在异常解冻或唤醒进程的应用
    mutex naughtyMutex;

    uint32_t timelineIdx = 0;
    uint32_t unfrozenTimeline[4096] = {};


    int refreezeSecRemain = 10; //开机压制
    int Memory_CompressLog = 1; // 内存压缩日志次数 

    std::atomic<int> remainTimesToRefreshTopApp;  // 使用原子进行操作

    static const size_t GET_VISIBLE_BUF_SIZE = 256 * 1024;
    unique_ptr<char[]> getVisibleAppBuff;

    const char* cgroupV2FreezerCheckPath = "/sys/fs/cgroup/uid_0/cgroup.freeze";
    const char* cgroupV2frozenCheckPath = "/sys/fs/cgroup/frozen/cgroup.freeze";       // "1" frozen
    const char* cgroupV2unfrozenCheckPath = "/sys/fs/cgroup/unfrozen/cgroup.freeze";   // "0" unfrozen

    const char* cpusetEventPath = "/dev/cpuset/top-app";

    const char* cgroupV1FrozenPath = "/dev/jark_freezer/frozen/cgroup.procs";
    const char* cgroupV1UnfrozenPath = "/dev/jark_freezer/unfrozen/cgroup.procs";
    
    // 如果直接使用 uid_xxx/cgroup.freeze 可能导致无法解冻
    const char* cgroupV2UidPidPath = "/sys/fs/cgroup/uid_%d/pid_%d/cgroup.freeze"; // "1"frozen   "0"unfrozen
    const char* cgroupV2FrozenPath = "/sys/fs/cgroup/frozen/cgroup.procs";         // write pid
    const char* cgroupV2UnfrozenPath = "/sys/fs/cgroup/unfrozen/cgroup.procs";     // write pid
    
    const char* ReKernel_Path = "/proc/rekernel";

    const char v2wchan[16] = "do_freezer_trap";      // FreezerV2冻结状态
    const char v1wchan[16] = "__refrigerator";       // FreezerV1冻结状态
    const char SIGSTOPwchan[16] = "do_signal_stop";  // SIGSTOP冻结状态
    const char v2xwchan[16] = "get_signal";          // FreezerV2冻结状态 内联状态
    const char pStopwchan[16] = "ptrace_stop";       // ptrace冻结状态
    const char epoll_wait1_wchan[16] = "SyS_epoll_wait";
    const char epoll_wait2_wchan[16] = "do_epoll_wait";

public:
    Freezer& operator=(Freezer&&) = delete;

    Freezer(Freezeit& freezeit, Settings& settings, ManagedApp& managedApp,
        SystemTools& systemTools, Doze& doze) :
        freezeit(freezeit), managedApp(managedApp), systemTools(systemTools),
        settings(settings), doze(doze) {

        getVisibleAppBuff = make_unique<char[]>(GET_VISIBLE_BUF_SIZE);

        threads.emplace_back(thread(&Freezer::cpuSetTriggerTask, this)); //监控前台
        threads.emplace_back(thread(&Freezer::cycleThreadFunc, this));
        if (settings.enableReKernel){
            threads.emplace_back(thread(&Freezer::binderEventTriggerTask, this)); //binder事件
        }

        checkFrozenV2(); // 禁止瞎挂载V2(Frozen)
        switch (static_cast<WORK_MODE>(settings.setMode)) {
        case WORK_MODE::V2FROZEN: {
            MountV2Frozen();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (checkFreezerV2FROZEN()) {
                workMode = WORK_MODE::V2FROZEN;
                freezeit.log("Freezer类型已设为 V2(FROZEN)");
                return;
            }
            freezeit.log("不支持自定义Freezer类型 V2(FROZEN)");
        } break;
        
        case WORK_MODE::V2UID: {
            if (checkFreezerV2UID()) {
                workMode = WORK_MODE::V2UID;
                freezeit.log("Freezer类型已设为 V2(UID)");
                return;
            }
            freezeit.log("不支持自定义Freezer类型 V2(UID)");
        } break;
        
        case WORK_MODE::V1FROZEN: {
            if (checkFreezerV1Frozen()) {
                workMode = WORK_MODE::V1FROZEN;
                freezeit.log("Freezer类型已设为 V1(FROZEN)");
                return;
            }
            freezeit.log("不支持自定义Freezer类型 V1(FROZEN)");
            mountFreezerV1();
        } return;

        case WORK_MODE::GLOBAL_SIGSTOP: {
            workMode = WORK_MODE::GLOBAL_SIGSTOP;
            freezeit.log("已设置[全局SIGSTOP], [Freezer冻结]将变为[SIGSTOP冻结]");
        } return;
        }

        // 以上手动选择若不支持或失败，下面将进行自动选择
        if (checkFreezerV2FROZEN()) {
            workMode = WORK_MODE::V2FROZEN;
            freezeit.log("Freezer类型已设为 V2(FROZEN)");
        }
        else if (checkFreezerV2UID()) {
            workMode = WORK_MODE::V2UID;
            freezeit.log("Freezer类型已设为 V2(UID)");
        }
        else if (checkFreezerV1Frozen()) {
            workMode = WORK_MODE::V1FROZEN;
            freezeit.log("Freezer类型已设为 V1(FROZEN)");
        }
        else {
            workMode = WORK_MODE::GLOBAL_SIGSTOP;
            freezeit.log("已开启 [全局SIGSTOP] 冻结模式");
        }
    }

    const char* getCurWorkModeStr() {
        switch (workMode)
        {
        case WORK_MODE::V2FROZEN:       return "FreezerV2 (FROZEN)";
        case WORK_MODE::V2UID:          return "FreezerV2 (UID)";
        case WORK_MODE::V1FROZEN:      return "FreezerV1 (FROZEN)";
        case WORK_MODE::GLOBAL_SIGSTOP: return "全局SIGSTOP";
        }
        return "未知";
    }

    void getPids(appInfoStruct& appInfo) {
        START_TIME_COUNT;

        appInfo.pids.clear();

        DIR* dir = opendir("/proc");
        if (dir == nullptr) {
            char errTips[256];
            snprintf(errTips, sizeof(errTips), "错误: %s() [%d]:[%s]", __FUNCTION__, errno,
                strerror(errno));
            fprintf(stderr, "%s", errTips);
            freezeit.log(errTips);
            return;
        }

        struct dirent* file;
        while ((file = readdir(dir)) != nullptr) {
            if (file->d_type != DT_DIR) continue;
            if (file->d_name[0] < '0' || file->d_name[0] > '9') continue;

            const int pid = atoi(file->d_name);
            if (pid <= 100) continue;

            char fullPath[64];
            memcpy(fullPath, "/proc/", 6);
            memcpy(fullPath + 6, file->d_name, 6);

            struct stat statBuf;
            if (stat(fullPath, &statBuf))continue;
            if (statBuf.st_uid != (uid_t)appInfo.uid) continue;

            strcat(fullPath + 8, "/cmdline");
            char readBuff[256];
            if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0)continue;
            const string& package = appInfo.package;
            if (strncmp(readBuff, package.c_str(), package.length())) continue;

            appInfo.pids.emplace_back(pid);
        }
        closedir(dir);
        END_TIME_COUNT;
    }

    //临时解冻
    void unFreezerTemporary(set<int>& uids) {
        curForegroundApp.insert(uids.begin(), uids.end());
        updateAppProcess();
    }

    void unFreezerTemporary(int uid) {
        curForegroundApp.insert(uid);
        updateAppProcess();
    }

    map<int, vector<int>> getRunningPids(set<int>& uidSet) {
        START_TIME_COUNT;
        map<int, vector<int>> pids;

        DIR* dir = opendir("/proc");
        if (dir == nullptr) {
            char errTips[256];
            snprintf(errTips, sizeof(errTips), "错误: %s() [%d]:[%s]", __FUNCTION__, errno,
                strerror(errno));
            fprintf(stderr, "%s", errTips);
            freezeit.log(errTips);
            return pids;
        }

        struct dirent* file;
        while ((file = readdir(dir)) != nullptr) {
            if (file->d_type != DT_DIR) continue;
            if (file->d_name[0] < '0' || file->d_name[0] > '9') continue;

            const int pid = atoi(file->d_name);
            if (pid <= 100) continue;

            char fullPath[64];
            memcpy(fullPath, "/proc/", 6);
            memcpy(fullPath + 6, file->d_name, 6);

            struct stat statBuf;
            if (stat(fullPath, &statBuf))continue;
            const int uid = statBuf.st_uid;
            if (!uidSet.contains(uid))continue;

            strcat(fullPath + 8, "/cmdline");
            char readBuff[256];
            if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0)continue;
            const string& package = managedApp[uid].package;
            if (strncmp(readBuff, package.c_str(), package.length())) continue;

            pids[uid].emplace_back(pid);
        }
        closedir(dir);
        END_TIME_COUNT;
        return pids;
    }

    set<int> getRunningUids(set<int>& uidSet) {
        START_TIME_COUNT;
        set<int> uids;

        DIR* dir = opendir("/proc");
        if (dir == nullptr) {
            char errTips[256];
            snprintf(errTips, sizeof(errTips), "错误: %s() [%d]:[%s]", __FUNCTION__, errno,
                strerror(errno));
            fprintf(stderr, "%s", errTips);
            freezeit.log(errTips);
            return uids;
        }

        struct dirent* file;
        while ((file = readdir(dir)) != nullptr) {
            if (file->d_type != DT_DIR) continue;
            if (file->d_name[0] < '0' || file->d_name[0] > '9') continue;

            const int pid = atoi(file->d_name);
            if (pid <= 100) continue;

            char fullPath[64];
            memcpy(fullPath, "/proc/", 6);
            memcpy(fullPath + 6, file->d_name, 6);

            struct stat statBuf;
            if (stat(fullPath, &statBuf))continue;
            const int uid = statBuf.st_uid;
            if (!uidSet.contains(uid))continue;

            strcat(fullPath + 8, "/cmdline");
            char readBuff[256];
            if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0)continue;
            const string& package = managedApp[uid].package;
            if (strncmp(readBuff, package.c_str(), package.length())) continue;

            uids.insert(uid);
        }
        closedir(dir);
        END_TIME_COUNT;
        return uids;
    }
    void memory_compress(const appInfoStruct& appInfo){
        if (Memory_CompressLog == 1) {
            freezeit.log("已开启 [内存压缩]"); 
            Memory_CompressLog = 0; // 不再输出日志
        } 
     // https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/core/jni/com_android_server_am_CachedAppOptimizer.cpp;bpv=1;bpt=1;l=274?q=compactProcess&ss=android%2Fplatform%2Fsuperproject%2Fmain&hl=zh-cn
            const char* action = "内存压缩";
            const char* compactionType = "file";
            for (const int pid : appInfo.pids) {
                char path[64];
                sprintf(path, "/proc/%d/reclaim", pid);
                    Utils::writeString(path, compactionType);
                        if (settings.enableDebug) 
                            freezeit.logFmt("%s [%s PID:%d]", action, appInfo.label.c_str(), pid);
            }
        }
    void handleSignal(const appInfoStruct& appInfo, const int signal) {
        if (signal == SIGKILL) {
            //先暂停 然后再杀，否则有可能会复活
            for (const auto pid : appInfo.pids) {
                freezeit.debugFmt("暂停 [%s:%d]", appInfo.label.c_str(), pid);
                kill(pid, SIGSTOP);
            }

            usleep(1000 * 50);
            for (const auto pid : appInfo.pids) {
                freezeit.debugFmt("终结 [%s:%d]", appInfo.label.c_str(), pid);
                kill(pid, SIGKILL);
            }

            return;
        }

        for (const int pid : appInfo.pids)
            if (kill(pid, signal) < 0 && signal == SIGSTOP)
                freezeit.logFmt("SIGSTOP冻结 [%s:%d] 失败[%s]",
                    appInfo.label.c_str(), pid, strerror(errno));
    }

    void handleFreezer(const appInfoStruct& appInfo, const bool freeze) {
        char path[256];
        const char* action = freeze ? "冻结" : "解冻";
        switch (workMode) {
        case WORK_MODE::V2FROZEN: {
            for (const int pid : appInfo.pids) {
                if (!Utils::writeInt(freeze ? cgroupV2FrozenPath : cgroupV2UnfrozenPath, pid))
                    freezeit.logFmt("%s [%s PID:%d] 失败(V2FROZEN)", action, appInfo.label.c_str(), pid);
            }
        } break;

        case WORK_MODE::V2UID: {
            for (const int pid : appInfo.pids) {
                snprintf(path, sizeof(path), cgroupV2UidPidPath, appInfo.uid, pid);
                if (!Utils::writeString(path, freeze ? "1" : "0", 2))
                    freezeit.logFmt("%s [%s PID:%d] 失败(进程可能已死亡)", action, appInfo.label.c_str(), pid);
            }
        } break;
        case WORK_MODE::V1FROZEN: {
            for (const int pid : appInfo.pids) {
                if (!Utils::writeInt(freeze ? cgroupV1FrozenPath : cgroupV1UnfrozenPath, pid))
                    freezeit.logFmt("%s [%s PID:%d] 失败(V1FROZEN)", action, appInfo.label.c_str(), pid);
            }
        } break;
        // 本函数只处理Freezer模式，其他冻结模式不应来到此处
        default: {
            freezeit.logFmt("%s 使用了错误的冻结模式", appInfo.label.c_str());
        } break;
        }
    }

    // < 0 : 冻结binder失败的pid， > 0 : 冻结成功的进程数
    int handleProcess(appInfoStruct& appInfo, const bool freeze) {
    START_TIME_COUNT;

    // 如果是冻结操作，获取进程的 PID
    if (freeze) {
        getPids(appInfo);
    }
    else {
        eraseInvalidPids(appInfo);
    }
        if (settings.enableMemoryCompress) {
            memory_compress(appInfo);
        }
    switch (appInfo.freezeMode) {
        case FREEZE_MODE::FREEZER:
        case FREEZE_MODE::FREEZER_BREAK:
            if (workMode != WORK_MODE::GLOBAL_SIGSTOP) {
                handleFreezer(appInfo, freeze);
                break;
            }
            // 如果是全局 WORK_MODE::GLOBAL_SIGSTOP，则继续执行
        case FREEZE_MODE::SIGNAL:
        case FREEZE_MODE::SIGNAL_BREAK:
            handleSignal(appInfo, freeze ? SIGSTOP : SIGCONT);
            break;

        case FREEZE_MODE::TERMINATE:
            if (freeze) 
                handleSignal(appInfo, SIGKILL);
            return 0; 

        default: 
        // 刚刚切到白名单，但仍在 pendingHandleList 时，就会执行到这里
            return 0; 
    }

    if (settings.isWakeupEnable()) {
        handleTimeline(appInfo, freeze);
    }

    if (freeze && appInfo.needBreakNetwork()) {
        handleNetworkBreak(appInfo);
    }

    END_TIME_COUNT;
    return appInfo.pids.size();
}

void eraseInvalidPids(appInfoStruct& appInfo) {
    erase_if(appInfo.pids, [&appInfo](const int pid) {
        char path[32] = {};
        snprintf(path, sizeof(path), "/proc/%d", pid);
        struct stat statBuf {};
        if (stat(path, &statBuf)) return true;
        return (uid_t)appInfo.uid != statBuf.st_uid;
    });
}

void handleTimeline(appInfoStruct& appInfo, const bool freeze) {
    if (0 <= appInfo.timelineUnfrozenIdx && appInfo.timelineUnfrozenIdx < 4096) {
        unfrozenTimeline[appInfo.timelineUnfrozenIdx] = 0;
    }

    if (freeze && appInfo.pids.size() && appInfo.isSignalOrFreezer()) {
        int nextIdx = (timelineIdx + settings.getWakeupTimeout()) & 0x0FFF; // [ %4096]
        while (unfrozenTimeline[nextIdx]) {
            nextIdx = (nextIdx + 1) & 0x0FFF;
        }
        appInfo.timelineUnfrozenIdx = nextIdx;
        unfrozenTimeline[nextIdx] = appInfo.uid;
    }
    else {
        appInfo.timelineUnfrozenIdx = -1;
    }
}

void handleNetworkBreak(appInfoStruct& appInfo) {
    const auto ret = systemTools.breakNetworkByLocalSocket(appInfo.uid);
    switch (static_cast<REPLY>(ret)) {
        case REPLY::SUCCESS:
            freezeit.logFmt("断网成功: %s", appInfo.label.c_str());
            break;
        case REPLY::FAILURE:
            freezeit.logFmt("断网失败: %s", appInfo.label.c_str());
            break;
        default:
            freezeit.logFmt("断网 未知回应[%d] %s", ret, appInfo.label.c_str());
            break;
    }
}

    // 重新压制第三方。 白名单, 前台, 待冻结列队 都跳过
    void checkReFreezeBackup() {
        START_TIME_COUNT;

        if (!settings.isRefreezeEnable()) return;

        if (--refreezeSecRemain > 0) return;
        refreezeSecRemain = settings.getRefreezeTimeout();

        lock_guard<mutex> lock(naughtyMutex);

        if (naughtyApp.size() == 0) {
            DIR* dir = opendir("/proc");
            if (dir == nullptr) {
                char errTips[256];
                snprintf(errTips, sizeof(errTips), "错误: %s() [%d]:[%s]", __FUNCTION__, errno,
                    strerror(errno));
                fprintf(stderr, "%s", errTips);
                freezeit.log(errTips);
                return;
            }

            struct dirent* file;
            while ((file = readdir(dir)) != nullptr) {
                if (file->d_type != DT_DIR) continue;
                if (file->d_name[0] < '0' || file->d_name[0] > '9') continue;

                const int pid = atoi(file->d_name);
                if (pid <= 100) continue;

                char fullPath[64];
                memcpy(fullPath, "/proc/", 6);
                memcpy(fullPath + 6, file->d_name, 6);

                struct stat statBuf;
                if (stat(fullPath, &statBuf))continue;
                const int uid = statBuf.st_uid;
                if (!managedApp.contains(uid) || pendingHandleList.contains(uid) || curForegroundApp.contains(uid))
                    continue;

                auto& appInfo = managedApp[uid];
                if (appInfo.isWhitelist())
                    continue;

                strcat(fullPath + 8, "/cmdline");
                char readBuff[256];
                if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0)continue;
                const auto& package = appInfo.package;
                if (strncmp(readBuff, package.c_str(), package.length())) continue;

                memcpy(fullPath + 6, file->d_name, 6);
                strcat(fullPath + 8, "/wchan");
                if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0)continue;
                if (strcmp(readBuff, v2wchan) && strcmp(readBuff, v1wchan) && strcmp(readBuff, SIGSTOPwchan) && 
                    strcmp(readBuff, v2xwchan) && strcmp(readBuff, pStopwchan)) {
                    naughtyApp.insert(uid);
                }
            }
            closedir(dir);
        }

        stackString<1024> tmp("定时压制");
        for (const auto uid : naughtyApp) {
            pendingHandleList[uid] = 1;
            tmp.append(' ').append(managedApp[uid].label.c_str());
        }
        if (naughtyApp.size()) {
            naughtyApp.clear();
            freezeit.log(string_view(tmp.c_str(), tmp.length));
        }
        else {
            freezeit.log("定时压制 目前均处于冻结状态");
        }

        END_TIME_COUNT;
    }


    // 临时解冻：检查已冻结应用的进程状态wchan，若有未冻结进程则临时解冻
    void checkUnFreeze() {
        START_TIME_COUNT;

        if (--refreezeSecRemain > 0) return;
        refreezeSecRemain = 3600;// 固定每小时检查一次

        lock_guard<mutex> lock(naughtyMutex);

        if (naughtyApp.size() == 0) {
            DIR* dir = opendir("/proc");
            if (dir == nullptr) {
                char errTips[256];
                snprintf(errTips, sizeof(errTips), "错误: %s() [%d]:[%s]", __FUNCTION__, errno,
                    strerror(errno));
                fprintf(stderr, "%s", errTips);
                freezeit.log(errTips);
                return;
            }

            struct dirent* file;
            while ((file = readdir(dir)) != nullptr) {
                if (file->d_type != DT_DIR) continue;
                if (file->d_name[0] < '0' || file->d_name[0] > '9') continue;

                const int pid = atoi(file->d_name);
                if (pid <= 100) continue;

                char fullPath[64];
                memcpy(fullPath, "/proc/", 6);
                memcpy(fullPath + 6, file->d_name, 6);

                struct stat statBuf;
                if (stat(fullPath, &statBuf))continue;
                const int uid = statBuf.st_uid;
                if (!managedApp.contains(uid) || pendingHandleList.contains(uid) || curForegroundApp.contains(uid))
                    continue;

                auto& appInfo = managedApp[uid];
                if (appInfo.isWhitelist())
                    continue;

                strcat(fullPath + 8, "/cmdline");
                char readBuff[256];
                if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0)continue;
                const auto& package = appInfo.package;
                if (strncmp(readBuff, package.c_str(), package.length())) continue;

                memcpy(fullPath + 6, file->d_name, 6);
                strcat(fullPath + 8, "/wchan");
                if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0)continue;
                if (strcmp(readBuff, v2wchan) && strcmp(readBuff, v1wchan) && strcmp(readBuff, SIGSTOPwchan) &&
                    strcmp(readBuff, v2xwchan) && strcmp(readBuff, pStopwchan)) {
                    naughtyApp.insert(uid);
                }
            }
            closedir(dir);
        }

        if (naughtyApp.size()) {
            stackString<1024> tmp("临时解冻");
            for (const auto uid : naughtyApp) {
                tmp.append(' ').append(managedApp[uid].label.c_str());
            }
            freezeit.log(string_view(tmp.c_str(), tmp.length));
            unFreezerTemporary(naughtyApp);
            naughtyApp.clear();
        }

        END_TIME_COUNT;
    }

    void mountFreezerV1() {
        freezeit.log("正在挂载Freezer V1(FROZEN)...");
        // https://man7.org/linux/man-pages/man7/cgroups.7.html
        // https://www.kernel.org/doc/Documentation/cgroup-v1/freezer-subsystem.txt
        // https://www.containerlabs.kubedaily.com/LXC/Linux%20Containers/The-cgroup-freezer-subsystem.html

        mkdir("/dev/jark_freezer", 0666);
        mount("freezer", "/dev/jark_freezer", "cgroup", 0, "freezer");
        usleep(1000 * 100);
        mkdir("/dev/jark_freezer/frozen", 0666);
        mkdir("/dev/jark_freezer/unfrozen", 0666);
        usleep(1000 * 100);
        Utils::writeString("/dev/jark_freezer/frozen/freezer.state", "FROZEN");
        Utils::writeString("/dev/jark_freezer/unfrozen/freezer.state", "THAWED");
  
        // https://www.spinics.net/lists/cgroups/msg24540.html
        // https://android.googlesource.com/device/google/crosshatch/+/9474191%5E%21/
        Utils::writeString("/dev/jark_freezer/frozen/freezer.killable", "1"); // 旧版内核不支持
        usleep(1000 * 100);

        if (checkFreezerV1Frozen()) {
            freezeit.log("Freezer V1(FROZEN)挂载成功");
        } else {
            freezeit.log("Freezer V1(FROZEN)挂载失败");
        }
    }
    bool checkFreezerV2UID() {
        return (!access(cgroupV2FreezerCheckPath, F_OK));
    }
    bool checkFreezerV1Frozen(){
        return (!access(cgroupV1FrozenPath, F_OK) && !access(cgroupV1UnfrozenPath, F_OK));
    }
    bool checkFreezerV2FROZEN() {
        return (!access(cgroupV2frozenCheckPath, F_OK) && !access(cgroupV2unfrozenCheckPath, F_OK));
    }
    bool checkReKernel(){
        return (!access(ReKernel_Path, F_OK));
    }
    void MountV2Frozen(){
        mkdir("/sys/fs/cgroup/frozen/", 0666);
        mkdir("/sys/fs/cgroup/unfrozen/", 0666);
        usleep(1000 * 500);

        if (checkFreezerV2FROZEN()) {
            auto fd = open(cgroupV2frozenCheckPath, O_WRONLY | O_TRUNC);
            if (fd > 0) {
                write(fd, "1", 2);
                close(fd);
            }
            freezeit.logFmt("设置%s FreezerV2(FROZEN)", fd > 0 ? "成功" : "失败");

            fd = open(cgroupV2unfrozenCheckPath, O_WRONLY | O_TRUNC);
            if (fd > 0) {
                write(fd, "0", 2);
                close(fd);
            }
            freezeit.logFmt("设置%s FreezerV2(UNFROZEN)", fd > 0 ? "成功" : "失败");
            freezeit.log("现已支持 FreezerV2(FROZEN)");
        }
    }
    void checkFrozenV2() {
        // https://cs.android.com/android/kernel/superproject/+/common-android12-5.10:common/kernel/cgroup/freezer.c

        if (checkFreezerV2UID())
            freezeit.log("原生支持 FreezerV2(UID)");

        if (checkFreezerV2FROZEN()) {
            freezeit.log("原生支持 FreezerV2(FROZEN)");
        }
    }

    void printProcState() {
        START_TIME_COUNT;

        DIR* dir = opendir("/proc");
        if (dir == nullptr) {
            freezeit.logFmt("错误: %s(), [%d]:[%s]\n", __FUNCTION__, errno, strerror(errno));
            return;
        }

        //int getSignalCnt = 0;
        int totalMiB = 0;
        set<int> uidSet, pidSet;

        lock_guard<mutex> lock(naughtyMutex);
        naughtyApp.clear();

        stackString<1024 * 16> stateStr("进程冻结状态:\n\n PID | MiB |  状 态  | 进 程\n");

        struct dirent* file;
        while ((file = readdir(dir)) != nullptr) {
            if (file->d_type != DT_DIR) continue;
            if (file->d_name[0] < '0' || file->d_name[0] > '9') continue;

            const int pid = atoi(file->d_name);
            if (pid <= 100) continue;

            char fullPath[64];
            memcpy(fullPath, "/proc/", 6);
            memcpy(fullPath + 6, file->d_name, 6);

            struct stat statBuf;
            if (stat(fullPath, &statBuf))continue;
            const int uid = statBuf.st_uid;
            if (!managedApp.contains(uid)) continue;

            auto& appInfo = managedApp[uid];
            if (appInfo.isWhitelist()) continue;

            strcat(fullPath + 8, "/cmdline");
            char readBuff[256]; // now is cmdline Content
            if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0)continue;
            const auto& package = appInfo.package;
            if (strncmp(readBuff, package.c_str(), package.length())) continue;

            uidSet.insert(uid);
            pidSet.insert(pid);

            stackString<256> label(appInfo.label.c_str(), appInfo.label.length());
            if (readBuff[appInfo.package.length()] == ':')
                label.append(readBuff + appInfo.package.length());

            memcpy(fullPath + 6, file->d_name, 6);
            strcat(fullPath + 8, "/statm");
            Utils::readString(fullPath, readBuff, sizeof(readBuff)); // now is statm content
            const char* ptr = strchr(readBuff, ' ');

            // Unit: 1 page(4KiB) convert to MiB. (atoi(ptr) * 4 / 1024)
            const int memMiB = ptr ? (atoi(ptr + 1) >> 8) : 0;
            totalMiB += memMiB;

            if (curForegroundApp.contains(uid)) {
                stateStr.appendFmt("%5d %4d 📱正在前台 %s\n", pid, memMiB, label.c_str());
                continue;
            }

            if (pendingHandleList.contains(uid)) {
                const auto secRemain = pendingHandleList[uid];
                if (secRemain < 60)
                    stateStr.appendFmt("%5d %4d ⏳%d秒后冻结 %s\n", pid, memMiB, secRemain, label.c_str());
                else
                    stateStr.appendFmt("%5d %4d ⏳%d分后冻结 %s\n", pid, memMiB, secRemain / 60, label.c_str());
                continue;
            }

            memcpy(fullPath + 6, file->d_name, 6);
            strcat(fullPath + 8, "/wchan");
            if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0) {
                uidSet.erase(uid);
                pidSet.erase(pid);
                continue;
            }

            stateStr.appendFmt("%5d %4d ", pid, memMiB);
            if (!strcmp(readBuff, v2wchan)) {
                stateStr.appendFmt("❄️V2冻结中 %s\n", label.c_str());
            }
            else if (!strcmp(readBuff, v1wchan)) {
                stateStr.appendFmt("❄️V1冻结中 %s\n", label.c_str());
            }
            else if (!strcmp(readBuff, SIGSTOPwchan)) {
                stateStr.appendFmt("🧊ST冻结中 %s\n", label.c_str());
            }
            else if (!strcmp(readBuff, v2xwchan)) {
                stateStr.appendFmt("❄️V2*冻结中 %s\n", label.c_str());
            }
            else if (!strcmp(readBuff, pStopwchan)) {
                stateStr.appendFmt("🧊ST冻结中(ptrace_stop) %s\n", label.c_str());
            }
            else if (!strcmp(readBuff, epoll_wait1_wchan) || !strcmp(readBuff, epoll_wait2_wchan)) {
                stateStr.appendFmt("⚠️运行中(就绪态) %s\n", label.c_str());
                naughtyApp.insert(uid);
            }
            else {
                stateStr.appendFmt("⚠️运行中(%s) %s\n", (const char*)readBuff, label.c_str());
                naughtyApp.insert(uid);
            }
        }
        closedir(dir);

        if (uidSet.size() == 0) {
            freezeit.log("后台很干净，一个黑名单应用都没有");
        }
        else {

            if (naughtyApp.size()) {
                stateStr.append("\n 发现 [未冻结状态] 的进程, 即将临时解冻\n");
                refreezeSecRemain = 0;
            }

            stateStr.appendFmt("\n总计 %d 应用 %d 进程, 占用内存 ", (int)uidSet.size(), (int)pidSet.size());
            stateStr.appendFmt("%.2f GiB", totalMiB / 1024.0);
            //if (getSignalCnt)
            //    stateStr.append(", V2*带星号状态为get_signal，小概率非冻结状态");

            freezeit.log(string_view(stateStr.c_str(), stateStr.length));
        }

        stackString<64> tips;
        int tmp = systemTools.runningTime;
        if (tmp >= 3600) {
            tips.append(tmp / 3600).append("时");
            tmp %= 3600;
        }
        if (tmp >= 60) {
            tips.append(tmp / 60).append("分");
            tmp %= 60;
        }
        tips.append(tmp).append("秒");
        freezeit.logFmt("满电至今已运行 %s", tips.c_str());

        END_TIME_COUNT;
    }

    // 解冻新APP, 旧APP加入待冻结列队
    void updateAppProcess() {
        bool isupdate = false;
        vector<int> newShowOnApp, toBackgroundApp;

        for (const int uid : curForegroundApp)
            if (!lastForegroundApp.contains(uid))
                newShowOnApp.emplace_back(uid);

        for (const int uid : lastForegroundApp)
            if (!curForegroundApp.contains(uid))
                toBackgroundApp.emplace_back(uid);

        if (newShowOnApp.empty() && toBackgroundApp.empty()) return;
            lastForegroundApp = curForegroundApp;

        for (const int uid : newShowOnApp) {
            // 如果在待冻结列表则只需移除
            if (pendingHandleList.erase(uid)) {
                isupdate = true;
                continue;
            }

            // 更新[打开时间]  并解冻
            auto& appInfo = managedApp[uid];
            appInfo.startTimestamp = time(nullptr);

            const int num = handleProcess(appInfo, false);
            if (num > 0)
                freezeit.logFmt("☀️解冻 %s %d进程", appInfo.label.c_str(), num);
            else 
                freezeit.logFmt("😁打开 %s", appInfo.label.c_str());
        }

        for (const int uid : toBackgroundApp) { // 更新倒计时
            isupdate = true;
            pendingHandleList[uid] = managedApp[uid].isTerminateMode() ?
                settings.terminateTimeout : settings.freezeTimeout;
        }

        if (isupdate)
            updatePendingByLocalSocket();
    }

    // 处理待冻结列队 call once per 1sec
    void processPendingApp() {
        bool isupdate = false;

        auto it = pendingHandleList.begin();
        while (it != pendingHandleList.end()) {
            auto& remainSec = it->second;
            if (--remainSec > 0) {//每次轮询减一
                it++;
                continue;
            }

            const int uid = it->first;
            auto& appInfo = managedApp[uid];

            if (appInfo.isWhitelist()) { // 刚切换成白名单的
                it = pendingHandleList.erase(it);
                continue;
            }

            int num = handleProcess(appInfo, true);
            it = pendingHandleList.erase(it);

            appInfo.stopTimestamp = time(nullptr);
            const int delta = appInfo.startTimestamp == 0 ? 0 :
                (appInfo.stopTimestamp - appInfo.startTimestamp);
            appInfo.startTimestamp = appInfo.stopTimestamp;
            appInfo.totalRunningTime += delta;
            const int total = appInfo.totalRunningTime;

            stackString<128> timeStr("运行");
            if (delta >= 3600) timeStr.appendFmt("%d时", delta / 3600);
            if (delta >= 60) timeStr.appendFmt("%d分", (delta % 3600) / 60);
            timeStr.appendFmt("%d秒", delta % 60);

            timeStr.append(" 累计", 7);
            if (total >= 3600) timeStr.appendFmt("%d时", total / 3600);
            if (total >= 60) timeStr.appendFmt("%d分", (total % 3600) / 60);
            timeStr.appendFmt("%d秒", total % 60);

            if (num)
                freezeit.logFmt("%s冻结 %s %d进程 %s",
                    appInfo.isSignalMode() ? "🧊" : "❄️",
                    appInfo.label.c_str(), num, timeStr.c_str());
            else 
                freezeit.logFmt("😭关闭 %s %s", appInfo.label.c_str(), timeStr.c_str());

            isupdate = true;
        }

        if (isupdate)
            updatePendingByLocalSocket();

    }

    void updatePendingByLocalSocket() {
        START_TIME_COUNT;

        int buff[64] = {};
        int uidCnt = 0;
        for (const auto& [uid, remainSec] : pendingHandleList) {
            buff[uidCnt++] = uid;
            if (uidCnt > 60)
                break;
        }

        const int recvLen = Utils::localSocketRequest(XPOSED_CMD::UPDATE_PENDING, buff,
            uidCnt * sizeof(int), buff, sizeof(buff));

        if (recvLen == 0) {
            freezeit.logFmt("%s() 工作异常, 请确认LSPosed中冻它勾选系统框架, 然后重启", __FUNCTION__);
            END_TIME_COUNT;
            return;
        }
        else if (recvLen != 4) {
            freezeit.logFmt("%s() 返回数据异常 recvLen[%d]", __FUNCTION__, recvLen);
            if (recvLen > 0 && recvLen < 64 * 4)
                freezeit.logFmt("DumpHex: %s", Utils::bin2Hex(buff, recvLen).c_str());
            END_TIME_COUNT;
            return;
        }
        else if (static_cast<REPLY>(buff[0]) == REPLY::FAILURE) {
            freezeit.log("Pending更新失败");
        }
        freezeit.debugFmt("pending更新 %d", uidCnt);
        END_TIME_COUNT;
        return;
    }

    void checkWakeup() {
        timelineIdx = (timelineIdx + 1) & 0x0FFF; // [ %4096]
        const auto uid = unfrozenTimeline[timelineIdx];
        if (uid == 0) return;

        unfrozenTimeline[timelineIdx] = 0;//清掉时间线当前位置UID信息

        if (!managedApp.contains(uid)) return;

        auto& appInfo = managedApp[uid];
        if (appInfo.isSignalOrFreezer()) {
            const int num = handleProcess(appInfo, false);
            if (num > 0) {
                appInfo.startTimestamp = time(nullptr);
                pendingHandleList[uid] = settings.freezeTimeout;//更新待冻结倒计时
                freezeit.logFmt("☀️定时解冻 %s %d进程", appInfo.label.c_str(), num);
            }
            else {
                freezeit.logFmt("🗑️后台被杀 %s", appInfo.label.c_str());
            }
        }
        else {
            appInfo.timelineUnfrozenIdx = -1;
        }
    }


    // 常规查询前台 只返回第三方, 剔除白名单/桌面
    void getVisibleAppByShell() {
        START_TIME_COUNT;

        curForegroundApp.clear();
        const char* cmdList[] = { "/system/bin/cmd", "cmd", "activity", "stack", "list", nullptr };
        VPOPEN::vpopen(cmdList[0], cmdList + 1, getVisibleAppBuff.get(), GET_VISIBLE_BUF_SIZE);

        stringstream ss;
        ss << getVisibleAppBuff.get();

        // 以下耗时仅为 VPOPEN::vpopen 的 2% ~ 6%
        string line;
        while (getline(ss, line)) {
            if (!managedApp.hasHomePackage() && line.find("mActivityType=home") != string::npos) {
                getline(ss, line); //下一行就是桌面信息
                auto startIdx = line.find_last_of('{');
                auto endIdx = line.find_last_of('/');
                if (startIdx == string::npos || endIdx == string::npos || startIdx > endIdx)
                    continue;

                managedApp.updateHomePackage(line.substr(startIdx + 1, endIdx - (startIdx + 1)));
            }

            //  taskId=8655: com.ruanmei.ithome/com.ruanmei.ithome.ui.MainActivity bounds=[0,1641][1440,3200]
            //     userId=0 visible=true topActivity=ComponentInfo{com.ruanmei.ithome/com.ruanmei.ithome.ui.NewsInfoActivity}
            if (!line.starts_with("  taskId=")) continue;
            if (line.find("visible=true") == string::npos) continue;

            auto startIdx = line.find_last_of('{');
            auto endIdx = line.find_last_of('/');
            if (startIdx == string::npos || endIdx == string::npos || startIdx > endIdx) continue;

            const string& package = line.substr(startIdx + 1, endIdx - (startIdx + 1));
            if (!managedApp.contains(package)) continue;
            int uid = managedApp.getUid(package);
            if (managedApp[uid].isWhitelist()) continue;
            curForegroundApp.insert(uid);
        }

        if (curForegroundApp.size() >= (lastForegroundApp.size() + 3)) //有时系统会虚报大量前台应用
            curForegroundApp = lastForegroundApp;

        END_TIME_COUNT;
    }
    /*
    void get_Millet_Binder_LocalSocket(){
        
        int buff[64];
        int recvLen = Utils::localSocketRequest(XPOSED_CMD::GET_MILLET_BINDER, nullptr, 0, buff,
            sizeof(buff));

        int& UidLen = buff[0];
        if (recvLen <= 0) {
            freezeit.logFmt("%s() 工作异常, 请确认LSPosed中冻它勾选系统框架, 然后重启", __FUNCTION__);
            return;
        }
    }
    */
    void getVisibleAppByLocalSocket() {
        START_TIME_COUNT;

        int buff[64];
        int recvLen = Utils::localSocketRequest(XPOSED_CMD::GET_FOREGROUND, nullptr, 0, buff,
            sizeof(buff));

        int& UidLen = buff[0];
        if (recvLen <= 0) {
            freezeit.logFmt("%s() 工作异常, 请确认LSPosed中冻它勾选系统框架, 然后重启", __FUNCTION__);
            END_TIME_COUNT;
            return;
        }
        else if (UidLen > 16 || (UidLen != (recvLen / 4 - 1))) {
            freezeit.logFmt("%s() 前台服务数据异常 UidLen[%d] recvLen[%d]", __FUNCTION__, UidLen, recvLen);
            freezeit.logFmt("DumpHex: %s", Utils::bin2Hex(buff, recvLen < 64 * 4 ? recvLen : 64 * 4).c_str());
            END_TIME_COUNT;
            return;
        }

        curForegroundApp.clear();
        for (int i = 1; i <= UidLen; i++) {
            int& uid = buff[i];
            if (managedApp.contains(uid)) curForegroundApp.insert(uid);
            else freezeit.logFmt("非法UID[%d], 可能是新安装的应用, 请点击右上角第一个按钮更新应用列表", uid);
        }

#if DEBUG_DURATION
        string tmp;
        for (auto& uid : curForegroundApp)
            tmp += " [" + managedApp[uid].label + "]";
        if (tmp.length())
            freezeit.logFmt("LOCALSOCKET前台%s", tmp.c_str());
        else
            freezeit.log("LOCALSOCKET前台 空");
#endif
        END_TIME_COUNT;
    }


    string getModeText(FREEZE_MODE mode) {
        switch (mode) {
        case FREEZE_MODE::TERMINATE:
            return "杀死后台";
        case FREEZE_MODE::SIGNAL:
            return "SIGSTOP冻结";
        case FREEZE_MODE::SIGNAL_BREAK:
            return "SIGSTOP冻结断网";
        case FREEZE_MODE::FREEZER:
            return "Freezer冻结";
        case FREEZE_MODE::FREEZER_BREAK:
            return "Freezer冻结断网";
        case FREEZE_MODE::WHITELIST:
            return "自由后台";
        case FREEZE_MODE::WHITEFORCE:
            return "自由后台(内置)";
        default:
            return "未知";
        }
    }

    void eventTouchTriggerTask(int n) {
        constexpr int TRIGGER_BUF_SIZE = 8192;

        char touchEventPath[64];
        snprintf(touchEventPath, sizeof(touchEventPath), "/dev/input/event%d", n);

        usleep(n * 1000 * 10);

        int inotifyFd = inotify_init();
        if (inotifyFd < 0) {
            fprintf(stderr, "同步事件: 0xA%d (1/3)失败: [%d]:[%s]", n, errno, strerror(errno));
            exit(-1);
        }

        int watch_d = inotify_add_watch(inotifyFd, touchEventPath, IN_ALL_EVENTS);
        if (watch_d < 0) {
            fprintf(stderr, "同步事件: 0xA%d (2/3)失败: [%d]:[%s]", n, errno, strerror(errno));
            exit(-1);
        }

        freezeit.logFmt("初始化同步事件: 0xA%d", n);

        constexpr int REMAIN_TIMES_MAX = 2;
        char buf[TRIGGER_BUF_SIZE];
        while (read(inotifyFd, buf, TRIGGER_BUF_SIZE) > 0) {
             remainTimesToRefreshTopApp.store(REMAIN_TIMES_MAX, std::memory_order_relaxed);
        }

        inotify_rm_watch(inotifyFd, watch_d);
        close(inotifyFd);

        freezeit.logFmt("已退出监控同步事件: 0xA%d", n);
    }

    void cpuSetTriggerTask() {

         sleep(1);

        int fd = inotify_init();
        if (fd < 0)  {
            fprintf(stderr, "同步事件: 0xB1 (1/3)失败: [%d]:[%s]", errno, strerror(errno));
            exit(-1);
        }


        int wd = inotify_add_watch(fd, cpusetEventPath, IN_ALL_EVENTS);
        if (wd < 0) {
            fprintf(stderr, "同步事件: 0xB1 (2/3)失败: [%d]:[%s]", errno, strerror(errno));
            close(fd);
            exit(-1);
        }

        freezeit.log("监听前台应用切换成功");

        const int buflen = sizeof(struct inotify_event) + NAME_MAX + 1;
        char buf[buflen];
        fd_set readfds;

        while (true) {
            FD_ZERO(&readfds);
            FD_SET(fd, &readfds);

            int iRet = select(fd + 1, &readfds, nullptr, nullptr, nullptr);
            if (iRet < 0) {
                break;
            }

            int len = read(fd, buf, buflen);
            if (len < 0) {
                fprintf(stderr, "同步事件: 0xB1 (3/3)失败: [%d]:[%s]", errno, strerror(errno));
                break;
            }
            constexpr int REMAIN_TIMES_MAX = 2;
            const struct inotify_event* event = reinterpret_cast<const struct inotify_event*>(buf);
            if (event->mask & IN_ALL_EVENTS) {
               remainTimesToRefreshTopApp.store(REMAIN_TIMES_MAX, std::memory_order_relaxed);
               std::this_thread::sleep_for(std::chrono::milliseconds(90)); 
            }
        }

        inotify_rm_watch(fd, wd);
        close(fd);

        freezeit.log("已退出监听前台应用切换");
    }

    // Binder事件 需要额外magisk模块: ReKernel
    void binderEventTriggerTask() {

        if (checkReKernel()) {
            freezeit.log("ReKernel已安装");
        }else{
            freezeit.log("ReKernel未安装");
            return;
        }
        int skfd;
        int ret;
        int NetLink_UserSock = NETLINK_USERSOCK;
        user_msg_info u_info;
        //socklen_t len;
        struct sockaddr_nl saddr, daddr;
        char umsg[] = "Hello! Re:Kernel!"; 

        std::string ReKernel_path = Utils::getNumberedFiles(ReKernel_Path);
        NetLink_UserSock = std::stoi(ReKernel_path);
        #define NetLink_UserSock NetLink_UserSock
        struct nlmsghdr* nlh = (struct nlmsghdr*)malloc(NLMSG_SPACE(MAX_PLOAD));

        while (true) {

            skfd = socket(AF_NETLINK, SOCK_RAW, NetLink_UserSock);
            if (skfd == -1) {
                freezeit.log("ReKernel AF_NETLINK 创建失败");
                sleep(60);
                continue;
            }

            memset(&saddr, 0, sizeof(saddr));
            saddr.nl_family = AF_NETLINK;
            saddr.nl_pid = USER_PORT;
            saddr.nl_groups = 0;
            if (bind(skfd, (struct sockaddr *)&saddr, sizeof(saddr)) != 0){
                close(skfd);

                freezeit.log("ReKernel bind 失败");
                sleep(60);
                continue;
            }
            memset(&daddr, 0, sizeof(daddr));
            daddr.nl_family = AF_NETLINK;
            daddr.nl_pid = 0;
            daddr.nl_groups = 0;

            free(nlh);
            nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PLOAD));
            memset(nlh, 0, sizeof(struct nlmsghdr));
            nlh->nlmsg_len = NLMSG_SPACE(MAX_PLOAD);
            nlh->nlmsg_flags = 0;
            nlh->nlmsg_type = 0;
            nlh->nlmsg_seq = 0;
            nlh->nlmsg_pid = saddr.nl_pid;

            memcpy(NLMSG_DATA(nlh), umsg, strlen(umsg));
            ret = sendto(skfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr_nl));
            if (ret < 0) {
                close(skfd);

                freezeit.log("ReKernel Failed send msg to kernel");
                sleep(60);
                continue;
            }
            while (true) {

                memset(&u_info, 0, sizeof(u_info));
                //len = sizeof(struct sockaddr_nl);

                char *ptr = strstr(u_info.msg, "target=");
                if (ptr != nullptr) {
                    const int uid = atoi(ptr + 7);
                    //待冻结列队 前台应用 白名单 黑名单跳过临时解冻
                    if (managedApp.contains(uid) && (!curForegroundApp.contains(uid))
                     && (!pendingHandleList.contains(uid))
                     && (!managedApp[uid].isBlacklist())) {
                        continue;
                       freezeit.logFmt("😋 ReKernel:临时解冻 %s", managedApp[uid].label.c_str());
                       unFreezerTemporary(uid);       
                    }         
                }
            }

                close(skfd);
                sleep(10);
        }

                free(nlh);
    }


    void cycleThreadFunc() {
        uint32_t halfSecondCnt{ 0 };

        sleep(1);
        getVisibleAppByShell(); // 获取桌面
        if (settings.enableBootFreezer) checkReFreezeBackup(); // 开机冻结
        
        while (true) {
            /*
            * 这里没必要休眠太久 重构后的cpuSetTriggerTask会自动堵塞
            */
           std::this_thread::sleep_for(std::chrono::milliseconds(90));
           if (remainTimesToRefreshTopApp > 0) {
                remainTimesToRefreshTopApp.fetch_sub(1);
                START_TIME_COUNT;
                if (doze.isScreenOffStandby) {
                    if (doze.checkIfNeedToExit()) {
                        curForegroundApp = std::move(curFgBackup); // recovery
                        updateAppProcess();
                    }
                }
                else {
                    getVisibleAppByLocalSocket();
                    updateAppProcess(); // ~40us
                }
                END_TIME_COUNT;
            }

            if (++halfSecondCnt & 1) continue;

            systemTools.cycleCnt++;
            systemTools.runningTime++;

            processPendingApp();//1秒一次

            // 2分钟一次 在亮屏状态检测是否已经息屏  息屏状态则检测是否再次强制进入深度Doze
            if (doze.checkIfNeedToEnter()) {
                curFgBackup = std::move(curForegroundApp); //backup
                updateAppProcess();
            }

            if (doze.isScreenOffStandby)continue;// 息屏状态 不用执行 以下功能

            systemTools.checkBattery();// 1分钟一次 电池检测
            checkUnFreeze();// 检查进程状态，按需临时解冻
            checkWakeup();// 检查是否有定时解冻
        }
    }


    void getBlackListUidRunning(set<int>& uids) {
        uids.clear();

        START_TIME_COUNT;

        DIR* dir = opendir("/proc");
        if (dir == nullptr) {
            char errTips[256];
            snprintf(errTips, sizeof(errTips), "错误: %s() [%d]:[%s]", __FUNCTION__, errno,
                strerror(errno));
            fprintf(stderr, "%s", errTips);
            freezeit.log(errTips);
            return;
        }

        struct dirent* file;
        while ((file = readdir(dir)) != nullptr) {
            if (file->d_type != DT_DIR) continue;
            if (file->d_name[0] < '0' || file->d_name[0] > '9') continue;

            const int pid = atoi(file->d_name);
            if (pid <= 100) continue;

            char fullPath[64];
            memcpy(fullPath, "/proc/", 6);
            memcpy(fullPath + 6, file->d_name, 6);

            struct stat statBuf;
            if (stat(fullPath, &statBuf))continue;
            const int uid = statBuf.st_uid;
            if (!managedApp.contains(uid) || managedApp[uid].isWhitelist())
                continue;

            strcat(fullPath + 8, "/cmdline");
            char readBuff[256];
            if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0)continue;
            const auto& package = managedApp[uid].package;
            if (strncmp(readBuff, package.c_str(), package.length())) continue;

            uids.insert(uid);
        }
        closedir(dir);
        END_TIME_COUNT;
    }

    int setWakeupLockByLocalSocket(const WAKEUP_LOCK mode) {
        static set<int> blackListUidRunning;
        START_TIME_COUNT;

        if (mode == WAKEUP_LOCK::IGNORE)
            getBlackListUidRunning(blackListUidRunning);

        if (blackListUidRunning.empty())return 0;

        int buff[64] = { static_cast<int>(blackListUidRunning.size()), static_cast<int>(mode) };
        int i = 2;
        for (const int uid : blackListUidRunning)
            buff[i++] = uid;

        const int recvLen = Utils::localSocketRequest(XPOSED_CMD::SET_WAKEUP_LOCK, buff,
            i * sizeof(int), buff, sizeof(buff));

        if (recvLen == 0) {
            freezeit.logFmt("%s() 工作异常, 请确认LSPosed中冻它勾选系统框架, 然后重启", __FUNCTION__);
            END_TIME_COUNT;
            return 0;
        }
        else if (recvLen != 4) {
            freezeit.logFmt("%s() 返回数据异常 recvLen[%d]", __FUNCTION__, recvLen);
            if (recvLen > 0 && recvLen < 64 * 4)
                freezeit.logFmt("DumpHex: %s", Utils::bin2Hex(buff, recvLen).c_str());
            END_TIME_COUNT;
            return 0;
        }
        END_TIME_COUNT;
        return buff[0];
    }

};
