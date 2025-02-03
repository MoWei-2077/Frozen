#pragma once

#include "utils.hpp"
#include "vpopen.hpp"
#include "managedApp.hpp"
#include "doze.hpp"
#include "freezeit.hpp"
#include "systemTools.hpp"

#define PACKET_SIZE      128
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
    mutex naughtyMutex;
	uint32_t timelineIdx = 0;
	uint32_t unfrozenTimeline[4096] = {};
	map<int, uint32_t> unfrozenIdx;
    int refreezeSecRemain = 20; //开机 一分钟时 就压一次
	static const size_t GET_VISIBLE_BUF_SIZE = 256 * 1024;
	unique_ptr<char[]> getVisibleAppBuff;
    
	struct binder_state {
		int fd = -1;
		void* mapped = nullptr;
		size_t mapSize = 128 * 1024;
	} bs;

	const char* cgroupV2FreezerCheckPath = "/sys/fs/cgroup/uid_0/cgroup.freeze";
	const char* cgroupV2frozenCheckPath = "/sys/fs/cgroup/frozen/cgroup.freeze";       // "1" frozen
	const char* cgroupV2unfrozenCheckPath = "/sys/fs/cgroup/unfrozen/cgroup.freeze";   // "0" unfrozen

	const char* cgroupV1FrozenPath = "/dev/jark_freezer/frozen/cgroup.procs";
	const char* cgroupV1UnfrozenPath = "/dev/jark_freezer/unfrozen/cgroup.procs";
	const char* cpusetEventPath = "/dev/cpuset/top-app";
	// 如果直接使用 uid_xxx/cgroup.freeze 可能导致无法解冻
	const char* cgroupV2UidPidPath = "/sys/fs/cgroup/uid_%d/pid_%d/cgroup.freeze"; // "1"frozen   "0"unfrozen
	const char* cgroupV2FrozenPath = "/sys/fs/cgroup/frozen/cgroup.procs";         // write pid
	const char* cgroupV2UnfrozenPath = "/sys/fs/cgroup/unfrozen/cgroup.procs";     // write pid
	const char* cgroupV2UidPath = "/sys/fs/cgroup/uid_%d/cgroup.freeze"; // "1"frozen   "0"unfrozen
    const char* reKernelPath = "/proc/rekernel";

	const char v2wchan[16] = "do_freezer_trap";      // FreezerV2冻结状态
	const char v1wchan[15] = "__refrigerator";       // FreezerV1冻结状态
	const char SIGSTOPwchan[15] = "do_signal_stop";  // SIGSTOP冻结状态
	const char v2xwchan[11] = "get_signal";          //不完整V2冻结状态
	const char epoll_wait1_wchan[15] = "SyS_epoll_wait";
	const char epoll_wait2_wchan[14] = "do_epoll_wait";
	const char binder_wchan[24] = "binder_ioctl_write_read";
	const char pipe_wchan[10] = "pipe_wait";

public:
	Freezer& operator=(Freezer&&) = delete;

	const string workModeStr(const WORK_MODE mode) {
		const string modeStrList[] = {
				"全局SIGSTOP",
				"FreezerV1 (FROZEN)",
				"FreezerV1 (FRZ+ST)",
				"FreezerV2 (UID)",
				"FreezerV2 (FROZEN)",
				"Unknown" };
		const uint32_t idx = static_cast<uint32_t>(mode);
		return modeStrList[idx <= 5 ? idx : 5];
	}

	Freezer(Freezeit& freezeit, Settings& settings, ManagedApp& managedApp,
		SystemTools& systemTools, Doze& doze) :
		freezeit(freezeit), managedApp(managedApp), systemTools(systemTools),
		settings(settings), doze(doze) {

		getVisibleAppBuff = make_unique<char[]>(GET_VISIBLE_BUF_SIZE);
        
	    if (freezeit.kernelVersion.main >= 5 && freezeit.kernelVersion.sub >= 10) {
		    const int res = binder_open("/dev/binder");
		    if (res > 0)
			    freezeit.logFmt("初始驱动 BINDER协议版本 %d", res);
		    else
		        freezeit.log("初始驱动 BINDER失败");
	    }

		threads.emplace_back(thread(&Freezer::cycleThreadFunc, this));
		threads.emplace_back(thread(&Freezer::ReKernel, this));
		checkFrozenV2();
		switch (static_cast<WORK_MODE>(settings.setMode)) {
		case WORK_MODE::GLOBAL_SIGSTOP: {
			workMode = WORK_MODE::GLOBAL_SIGSTOP;
			freezeit.setWorkMode(workModeStr(workMode));
			freezeit.log("已设置[全局SIGSTOP], [Freezer冻结]将变为[SIGSTOP冻结]");
		} return;

		case WORK_MODE::V1F: {
			if (mountFreezerV1()) {
				workMode = WORK_MODE::V1F;
				freezeit.setWorkMode(workModeStr(workMode));
				freezeit.log("Freezer类型已设为 V1(FROZEN)");
				return;
			}
			freezeit.log("不支持自定义Freezer类型 V1(FROZEN) 失败");
		} break;

		case WORK_MODE::V1F_ST: {
			if (mountFreezerV1()) {
				workMode = WORK_MODE::V1F_ST;
				freezeit.setWorkMode(workModeStr(workMode));
				freezeit.log("Freezer类型已设为 V1(FRZ+ST)");
				return;
			}
			freezeit.log("不支持自定义Freezer类型 V1(FRZ+ST)");
		} break;

		case WORK_MODE::V2UID: {
			if (checkFreezerV2UID()) {
				workMode = WORK_MODE::V2UID;
				freezeit.setWorkMode(workModeStr(workMode));
				freezeit.log("Freezer类型已设为 V2(UID)");
				return;
			}
			freezeit.log("不支持自定义Freezer类型 V2(UID)");
		} break;

		case WORK_MODE::V2FROZEN: {
			if (checkFreezerV2FROZEN()) {
				MountV2Frozen();
				workMode = WORK_MODE::V2FROZEN;
				freezeit.setWorkMode(workModeStr(workMode));
				freezeit.log("Freezer类型已设为 V2(FROZEN)");
				return;
			}
			freezeit.log("不支持自定义Freezer类型 V2(FROZEN)");
		} break;
		}

		if (checkFreezerV2FROZEN()) {
			workMode = WORK_MODE::V2FROZEN;
			freezeit.log("Freezer类型已设为 V2(FROZEN)");
		}
		else if (checkFreezerV2UID()) {
			workMode = WORK_MODE::V2UID;
			freezeit.log("Freezer类型已设为 V2(UID)");
		}
		else if (mountFreezerV1()) {
			workMode = WORK_MODE::V1F;
			freezeit.log("Freezer类型已设为 V1(FROZEN)");
		}
		else {
			workMode = WORK_MODE::GLOBAL_SIGSTOP;
			freezeit.log("不支持任何Freezer, 已开启 [全局SIGSTOP] 冻结模式");
		}
		freezeit.setWorkMode(workModeStr(workMode));
	}

	bool isV1Mode() {
		return workMode == WORK_MODE::V1F_ST || workMode == WORK_MODE::V1F;
	}

	void getPids(appInfoStruct& info, const int uid) {
		START_TIME_COUNT;

		info.pids.clear();

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
			if (statBuf.st_uid != (uid_t)uid) continue;

			strcat(fullPath + 8, "/cmdline");
			char readBuff[256];
			if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0)continue;
			const string& package = info.package;
			if (strncmp(readBuff, package.c_str(), package.length())) continue;
			const char endChar = readBuff[package.length()];
			if (endChar != ':' && endChar != 0)continue;

			info.pids.emplace_back(pid);
		}
		closedir(dir);
		END_TIME_COUNT;
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

	void handleSignal(const int uid, const vector<int>& pids, const int signal) {
		if (signal == SIGKILL) {
			if (isV1Mode() && managedApp[uid].isFreezeMode())
				handleFreezer(uid, pids, SIGCONT);  // 先给V1解冻， 否则无法杀死

			//先暂停 然后再杀，否则有可能会复活
			usleep(1000 * 50);
			for (const auto pid : pids)
				kill(pid, SIGSTOP);

			usleep(1000 * 50);
			for (const auto pid : pids)
				kill(pid, SIGKILL);

			return;
		}

		for (const int pid : pids)
			if (kill(pid, signal) < 0 && signal == SIGSTOP)
				freezeit.logFmt("SIGSTOP冻结 [%s PID:%d] 失败[%s]",
					managedApp[uid].label.c_str(), pid, strerror(errno));
	}

	void handleFreezer(const int uid, const vector<int>& pids, const int signal) {
		char path[256];
        bool HighEfficiency = true;
		switch (workMode) {
		case WORK_MODE::V2FROZEN: {
			for (const int pid : pids) {
				if (!Utils::writeInt(
					signal == SIGSTOP ? cgroupV2FrozenPath : cgroupV2UnfrozenPath, pid))
					freezeit.logFmt("%s [%s PID:%d] 失败(V2FROZEN)",
						(signal == SIGSTOP ? "冻结" : "解冻"),
						managedApp[uid].label.c_str(), pid);
			}
		} break;

		case WORK_MODE::V2UID: {
			/*if (HighEfficiency) {
				snprintf(path, sizeof(path), cgroupV2UidPath, uid);
				if (!Utils::writeInt(path, signal == SIGSTOP ? 1 : 0))
					freezeit.logFmt("%s [%s UID:%d] 失败(进程可能已死亡)",
							(signal == SIGSTOP ? "冻结" : "解冻"),
					managedApp[uid].label.c_str(), uid);
			} else {*/
				for (const int pid : pids) {
					snprintf(path, sizeof(path), cgroupV2UidPidPath, uid, pid);
					if (!Utils::writeString(path, signal == SIGSTOP ? "1" : "0", 2))
						freezeit.logFmt("%s [%s PID:%d] 失败(进程可能已死亡)",
							(signal == SIGSTOP ? "冻结" : "解冻"),
						managedApp[uid].label.c_str(), pid);
					}
		//	}
		} break;

		case WORK_MODE::V1F_ST: {
			if (signal == SIGSTOP) {
				for (const int pid : pids) {
					if (!Utils::writeInt(cgroupV1FrozenPath, pid))
						freezeit.logFmt("冻结 [%s PID:%d] 失败(V1F_ST_F)",
							managedApp[uid].label.c_str(), pid);
					if (kill(pid, signal) < 0)
						freezeit.logFmt("冻结 [%s PID:%d] 失败(V1F_ST_S)",
							managedApp[uid].label.c_str(), pid);
				}
			}
			else {
				for (const int pid : pids) {
					if (kill(pid, signal) < 0)
						freezeit.logFmt("解冻 [%s PID:%d] 失败(V1F_ST_S)",
							managedApp[uid].label.c_str(), pid);
					if (!Utils::writeInt(cgroupV1UnfrozenPath, pid))
						freezeit.logFmt("解冻 [%s PID:%d] 失败(V1F_ST_F)",
							managedApp[uid].label.c_str(), pid);
				}
			}
		} break;

		case WORK_MODE::V1F: {
			for (const int pid : pids) {
				if (!Utils::writeInt(
					signal == SIGSTOP ? cgroupV1FrozenPath : cgroupV1UnfrozenPath, pid))
					freezeit.logFmt("%s [%s] 失败(V1F) PID:%d", (signal == SIGSTOP ? "冻结" : "解冻"),
						managedApp[uid].label.c_str(), pid);
			}
		} break;

		// 本函数只处理Freezer模式，其他冻结模式不应来到此处
		default: {
			freezeit.logFmt("%s 使用了错误的冻结模式", managedApp[uid].label.c_str());
		} break;
		}
	}

	// 只接受 SIGSTOP SIGCONT
	int handleProcess(appInfoStruct& info, const int uid, const int signal) {
		START_TIME_COUNT;

		if (signal == SIGSTOP)
			getPids(info, uid);
		else if (signal == SIGCONT) {
			erase_if(info.pids, [](const int pid) {
				char path[16];
				snprintf(path, sizeof(path), "/proc/%d", pid);
				return access(path, F_OK);
				});
		}
		else {
			freezeit.logFmt("错误执行 %s %d", info.label.c_str(), signal);
			return 0;
		}

		switch (info.freezeMode) {
		case FREEZE_MODE::FREEZER: 
		case FREEZE_MODE::FREEZER_BREAK: {
			if (workMode != WORK_MODE::GLOBAL_SIGSTOP) {
				handleFreezer(uid, info.pids, signal);
				break;
			}
			// 如果是全局 WORK_MODE::GLOBAL_SIGSTOP 则顺着执行下面
		}
        case FREEZE_MODE::BINDER_FREEZER:{
		    if (workMode != WORK_MODE::GLOBAL_SIGSTOP) {
				const int res = handleBinder(info.pids, signal);
				if (res < 0 && signal == SIGSTOP && info.isTolerant)
					return res;
				handleFreezer(uid, info.pids, signal);
				break;
			}
		}
		case FREEZE_MODE::SIGNAL:
		case FREEZE_MODE::SIGNAL_BREAK: {
			handleSignal(uid, info.pids, signal);
		} break;

		case FREEZE_MODE::TERMINATE: {
			if (signal == SIGSTOP)
				handleSignal(uid, info.pids, SIGKILL);
			return 0;
		}

		default: {
			return 0;
		}
		}

		if (settings.wakeupTimeoutMin != 120) {
			// 无论冻结还是解冻都要清除 解冻时间线上已设置的uid
			auto it = unfrozenIdx.find(uid);
			if (it != unfrozenIdx.end())
				unfrozenTimeline[it->second] = 0;

			// 冻结就需要在 解冻时间线 插入下一次解冻的时间
			if (signal == SIGSTOP && info.pids.size() &&
                info.freezeMode != FREEZE_MODE::TERMINATE) {
                uint32_t nextIdx = (timelineIdx + settings.wakeupTimeoutMin * 60) & 0x0FFF; 
                unfrozenIdx[uid] = nextIdx;
                unfrozenTimeline[nextIdx] = uid;
				
            } else {
                unfrozenIdx.erase(uid);
			}
		}

		if (signal == SIGSTOP && info.needBreakNetwork()) {
			const auto ret = systemTools.breakNetworkByLocalSocket(uid);
			switch (static_cast<REPLY>(ret)) {
			case REPLY::SUCCESS:
				freezeit.logFmt("断网成功: %s", info.label.c_str());
				break;
			case REPLY::FAILURE:
				freezeit.logFmt("断网失败: %s", info.label.c_str());
				break;
			default:
				freezeit.logFmt("断网 未知回应[%d] %s", ret, info.label.c_str());
				break;
			}
		}

		END_TIME_COUNT;
		return info.pids.size();
	}

	// 重新压制第三方。 白名单, 前台, 待冻结列队 都跳过
	void BootFreezer() {
		START_TIME_COUNT;

		if (--refreezeSecRemain > 0) return;

		refreezeSecRemain = settings.getRefreezeTimeout();

		map<int, vector<int>> terminateList, SIGSTOPList, freezerList;

		DIR* dir = opendir("/proc");
		if (dir == nullptr) {
			char errTips[256];
			snprintf(errTips, sizeof(errTips), "错误: %s() [%d]:[%s]", __FUNCTION__, errno,
				strerror(errno));
			fprintf(stderr, "%s", errTips);
			freezeit.log(errTips);
			return;
		}

		vector<int> pushPids;

		struct dirent* file;
		while ((file = readdir(dir)) != nullptr) {
			if (file->d_type != DT_DIR) continue;
			if (file->d_name[0] < '0' || file->d_name[0] > '9') continue;

			int pid = atoi(file->d_name);
			if (pid <= 100) continue;

			char fullPath[64];
			memcpy(fullPath, "/proc/", 6);
			memcpy(fullPath + 6, file->d_name, 6);

			struct stat statBuf;
			if (stat(fullPath, &statBuf))continue;
			const int uid = statBuf.st_uid;
			if (managedApp.without(uid)) continue;

			auto& info = managedApp[uid];
			if (info.isWhitelist() || pendingHandleList.contains(uid) || curForegroundApp.contains(uid))
				continue;

			strcat(fullPath + 8, "/cmdline");
			char readBuff[256];
			if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0)continue;
			if (strncmp(readBuff, info.package.c_str(), info.package.length())) continue;

			switch (info.freezeMode) {
			case FREEZE_MODE::TERMINATE:
				terminateList[uid].emplace_back(pid);
				break;
			case FREEZE_MODE::FREEZER:
			case FREEZE_MODE::FREEZER_BREAK:
				if (workMode != WORK_MODE::GLOBAL_SIGSTOP) {
					freezerList[uid].emplace_back(pid);
					break;
				}
			case FREEZE_MODE::BINDER_FREEZER:
			case FREEZE_MODE::SIGNAL:
			case FREEZE_MODE::SIGNAL_BREAK:
			default:
				SIGSTOPList[uid].emplace_back(pid);
				break;
			}
		}
		closedir(dir);

		//vector<int> breakList;
		stackString<1024> tmp;
		for (const auto& [uid, pids] : freezerList) {
			auto& info = managedApp[uid];
			tmp.append(" ", 1).append(info.label.c_str(), (int)info.label.length());
			handleFreezer(uid, pids, SIGSTOP);
			managedApp[uid].pids = std::move(pids);

			//if (info.needBreakNetwork())
			//	breakList.emplace_back(uid);
		}
		if (tmp.length) freezeit.logFmt("定时Freezer压制: %s", tmp.c_str());

		tmp.clear();
		for (auto& [uid, pids] : SIGSTOPList) {
			auto& info = managedApp[uid];
			tmp.append(" ", 1).append(info.label.c_str(), (int)info.label.length());
			handleSignal(uid, pids, SIGSTOP);
			managedApp[uid].pids = std::move(pids);

			//if (info.needBreakNetwork())
			//	breakList.emplace_back(uid);
		}
		if (tmp.length) freezeit.logFmt("定时SIGSTOP压制: %s", tmp.c_str());

		tmp.clear();
		for (const auto& [uid, pids] : terminateList) {
			auto& label = managedApp[uid].label;
			tmp.append(" ", 1).append(label.c_str(), (int)label.length());
			handleSignal(uid, pids, SIGKILL);
		}
		if (tmp.length) freezeit.logFmt("定时压制 杀死后台: %s", tmp.c_str());

		for (const int pid : pushPids)
			kill(pid, SIGKILL);

		END_TIME_COUNT;
	}

	bool mountFreezerV1() {
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
        Utils::WriteFile("/dev/jark_freezer/frozen/freezer.state", "FROZEN");
        Utils::WriteFile("/dev/jark_freezer/unfrozen/freezer.state", "THAWED");
  
        // https://www.spinics.net/lists/cgroups/msg24540.html
        // https://android.googlesource.com/device/google/crosshatch/+/9474191%5E%21/
        Utils::WriteFile("/dev/jark_freezer/frozen/freezer.killable", "1"); // 旧版内核不支持
        usleep(1000 * 100);

        if (checkFreezerV1Frozen()) {
            freezeit.log("Freezer V1(FROZEN)挂载成功");
			return true;
        } else {
            freezeit.log("Freezer V1(FROZEN)挂载失败");
			return false;
        }
    }
    bool checkFreezerV1Frozen() {
		return (!access(cgroupV1FrozenPath, F_OK) && !access(cgroupV1UnfrozenPath, F_OK));
	}
	bool checkFreezerV2UID() {
		return (!access(cgroupV2FreezerCheckPath, F_OK));
	}

	bool checkFreezerV2FROZEN() {
		return (!access(cgroupV2frozenCheckPath, F_OK) && !access(cgroupV2unfrozenCheckPath, F_OK));
	}
    
	bool checkReKernel() {
		return (!access(reKernelPath, F_OK));
	}
    void checkFrozenV2() {
        // https://cs.android.com/android/kernel/superproject/+/common-android12-5.10:common/kernel/cgroup/freezer.c

        if (checkFreezerV2UID())
            freezeit.log("原生支持 FreezerV2(UID)");

        if (checkFreezerV2FROZEN()) {
            freezeit.log("原生支持 FreezerV2(FROZEN)");
        }
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
	void printProcState() {
		START_TIME_COUNT;

		DIR* dir = opendir("/proc");
		if (dir == nullptr) {
			freezeit.logFmt("错误: %s(), [%d]:[%s]\n", __FUNCTION__, errno, strerror(errno));
			return;
		}

		int totalMiB = 0;
		bool needRefrezze = false;
		set<int> uidSet, pidSet;

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
			if (managedApp.without(uid)) continue;

			auto& info = managedApp[uid];
			if (info.isWhitelist()) continue;

			strcat(fullPath + 8, "/cmdline");
			char readBuff[256]; // now is cmdline Content
			if (Utils::readString(fullPath, readBuff, sizeof(readBuff)) == 0)continue;
			if (strncmp(readBuff, info.package.c_str(), info.package.length())) continue;

			uidSet.insert(uid);
			pidSet.insert(pid);

			stackString<256> label(info.label.c_str(), info.label.length());
			if (readBuff[info.package.length()] == ':')
				label.append(readBuff + info.package.length());

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
				stateStr.appendFmt("%5d %4d ⏳等待冻结 %s\n", pid, memMiB, label.c_str());
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
			if (!strcmp(readBuff, v2wchan) || !strcmp(readBuff, v2xwchan)) {
				stateStr.appendFmt("❄️V2冻结中 %s\n", label.c_str());
			}
			else if (!strcmp(readBuff, v1wchan)) {
				stateStr.appendFmt("❄️V1冻结中 %s\n", label.c_str());
			}
			else if (!strcmp(readBuff, SIGSTOPwchan)) {
				stateStr.appendFmt("🧊ST冻结中 %s\n", label.c_str());
			}
			else if (!strcmp(readBuff, binder_wchan)) {
				stateStr.appendFmt("⚠️运行中(Binder通信) %s\n", label.c_str());
				needRefrezze = true;
			}
			else if (!strcmp(readBuff, pipe_wchan)) {
				stateStr.appendFmt("⚠️运行中(管道通信) %s\n", label.c_str());
				needRefrezze = true;
			}
			else if (!strcmp(readBuff, epoll_wait1_wchan) || !strcmp(readBuff, epoll_wait2_wchan)) {
				stateStr.appendFmt("⚠️运行中(就绪态) %s\n", label.c_str());
				needRefrezze = true;
			}
			else {
				stateStr.appendFmt("⚠️运行中(%s) %s\n", (const char*)readBuff, label.c_str());
				needRefrezze = true;
			}
		}
		closedir(dir);

		if (uidSet.size() == 0) {
			freezeit.log("设为冻结的应用没有运行");
		}
		else {

			if (needRefrezze) {
				stateStr.append("\n ⚠️ 发现 [未冻结] 的进程, 即将进行临时冻结 ⚠️\n", 65);
				refreezeSecRemain = 0;
			}

			stateStr.appendFmt("\n总计 %d 应用 %d 进程, 占用内存 ", (int)uidSet.size(), (int)pidSet.size());
			stateStr.appendFmt("%.2f GiB", totalMiB / 1024.0);
			if (isV1Mode())
				stateStr.append(", V1已冻结状态可能会识别为[运行中]，请到[CPU使用时长]页面查看是否跳动", 98);

			freezeit.log(stateStr.c_str());
		}
		END_TIME_COUNT;
	}

	// 解冻新APP, 旧APP加入待冻结列队 call once per 0.5 sec when Touching
	void updateAppProcess() {
		vector<int> newShowOnApp, switch2BackApp;

		for (const int uid : curForegroundApp)
			if (!lastForegroundApp.contains(uid))
				newShowOnApp.emplace_back(uid);

		for (const int uid : lastForegroundApp)
			if (!curForegroundApp.contains(uid))
				switch2BackApp.emplace_back(uid);

		if (newShowOnApp.size() || switch2BackApp.size())
			lastForegroundApp = curForegroundApp;
		else
			return;

		for (const int uid : newShowOnApp) {
			// 如果在待冻结列表则只需移除
			if (pendingHandleList.erase(uid))
				continue;

			// 更新[打开时间]  并解冻
			auto& info = managedApp[uid];
			info.startRunningTime = time(nullptr);

			const int num = handleProcess(info, uid, SIGCONT);
			if (num > 0) freezeit.logFmt("☀️解冻 %s %d进程", info.label.c_str(), num);
			else freezeit.logFmt("😁打开 %s", info.label.c_str());
		}

		for (const int uid : switch2BackApp) // 更新倒计时
			pendingHandleList[uid] = managedApp[uid].isTerminateMode() ? 
			settings.terminateTimeout : settings.freezeTimeout;
	}
	// 处理待冻结列队 call once per 1sec
	void processPendingApp() {
		auto it = pendingHandleList.begin();
		while (it != pendingHandleList.end()) {
			auto& remainSec = it->second;
			if (--remainSec > 0) {//每次轮询减一
				it++;
				continue;
			}

			const int uid = it->first;
			auto& info = managedApp[uid];
			const int num = handleProcess(info, uid, SIGSTOP);
	
			it = pendingHandleList.erase(it);
			info.failFreezeCnt = 0;

			info.stopRunningTime = time(nullptr);
			const int delta = info.startRunningTime == 0 ? 0:
				(info.stopRunningTime - info.startRunningTime);
			info.totalRunningTime += delta;
			const int total = info.totalRunningTime;

			stackString<128> timeStr("运行");
			if (delta >= 3600)
				timeStr.appendFmt("%d时", delta / 3600);
			if (delta >= 60)
				timeStr.appendFmt("%d分", (delta % 3600) / 60);
			timeStr.appendFmt("%d秒", delta % 60);

			timeStr.append(" 累计", 7);
			if (total >= 3600)
				timeStr.appendFmt("%d时", total / 3600);
			if (total >= 60)
				timeStr.appendFmt("%d分", (total % 3600) / 60);
			timeStr.appendFmt("%d秒", total % 60);

			if (!num) {
				freezeit.logFmt("😭关闭 %s %s", info.label.c_str(), *timeStr);
				return;
			}
			
			freezeit.logFmt("%s冻结 %s %d进程 %s",
			info.isSignalMode() ? "🧊" : "❄️",
			info.label.c_str(), num, timeStr.c_str());

		}
	}

	void checkWakeup() {
		timelineIdx = (timelineIdx + 1) & 0x0FFF; // [ %4096]
		const auto uid = unfrozenTimeline[timelineIdx];
		if (uid == 0) return;

		unfrozenTimeline[timelineIdx] = 0;//清掉时间线当前位置UID信息

		if (managedApp.without(uid)) return;

		auto& info = managedApp[uid];
		if (!info.needFreezer()) {
			unfrozenIdx.erase(uid);
            return;
		}

		const int num = handleProcess(info, uid, SIGCONT);
		if (num < 0) {
			freezeit.logFmt("🗑️后台被杀 %s", info.label.c_str());
            return;
		}

		info.startRunningTime = time(nullptr);
		pendingHandleList[uid] = settings.freezeTimeout;//更新待冻结倒计时
		freezeit.logFmt("☀️定时解冻 %s %d进程", info.label.c_str(), num);
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
			if (managedApp.without(package)) continue;
			int uid = managedApp.getUid(package);
			if (managedApp[uid].isWhitelist()) continue;
			curForegroundApp.insert(uid);
		}

		if (curForegroundApp.size() >= (lastForegroundApp.size() + 3)) //有时系统会虚报大量前台应用
			curForegroundApp = lastForegroundApp;

		END_TIME_COUNT;
	}

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
		case FREEZE_MODE::BINDER_FREEZER:
		    return "冻结Binder";
		case FREEZE_MODE::WHITELIST:
			return "自由后台";
		case FREEZE_MODE::WHITEFORCE:
			return "自由后台(内置)";
		default:
			return "未知";
		}
	}
	
    void InotifyMain(const char* path) {
        int fd = inotify_init();
        if (fd < 0) {
            fprintf(stderr, "同步事件: 0xB1 (1/3)失败: [%d]:[%s]", errno, strerror(errno));
            exit(-1);
        }

        int wd = inotify_add_watch(fd, path, IN_ALL_EVENTS);
        if (wd < 0) {
            fprintf(stderr, "同步事件: 0xB1 (2/3)失败: [%d]:[%s]", errno, strerror(errno));
            close(fd);
            exit(-1);
        }

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

            const struct inotify_event* event = reinterpret_cast<const struct inotify_event*>(buf);
            if (event->mask & IN_ALL_EVENTS) {
				break; 
            }
        }

        inotify_rm_watch(fd, wd);
        close(fd);
    }
	int GetReKernelFileName(char *buffer, size_t buffer_size) {
    	DIR *dir;
    	struct dirent *entry;

    	dir = opendir(reKernelPath);
    	if (!dir) {
        	perror("Failed to open /proc/rekernel/");
			freezeit.log("未找到rekernel文件");
        	return -1;
    	}

    	while ((entry = readdir(dir)) != NULL) {
        	if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            	continue;
        	}

        	strncpy(buffer, entry->d_name, buffer_size - 1);
        	buffer[buffer_size - 1] = '\0'; 
       	 	break;
    	}

    	closedir(dir);

    	return 0;
	}
	void ReKernel() {
        int NETLINK_UNIT = 0;
    	int skfd;
    	int ret;
    	user_msg_info u_info;
    	socklen_t len;
    	struct nlmsghdr nlh;
    	struct sockaddr_nl saddr, daddr;
    	const char *umsg = "Hello! Re:Kernel!";
        if (!checkReKernel()) {
            freezeit.log("ReKernel未安装");
            return;
		}
		char buffer[256];
        if (GetReKernelFileName(buffer, sizeof(buffer)) == 0) {
			NETLINK_UNIT = atoi(buffer);
        }

    	skfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_UNIT);
    	if (skfd == -1) {
        	freezeit.log("创建NetLink失败");
        	exit(-1);
    	}

    	memset(&saddr, 0, sizeof(saddr));
    	saddr.nl_family = AF_NETLINK;
    	saddr.nl_pid = USER_PORT;
    	saddr.nl_groups = 0;
    	if (bind(skfd, (struct sockaddr *)&saddr, sizeof(saddr)) != 0) {
        	freezeit.log("连接Bind失败");
        	close(skfd);
        	exit(-1);
    	}

    	memset(&daddr, 0, sizeof(daddr));
    	daddr.nl_family = AF_NETLINK;
    	daddr.nl_pid = 0;
    	daddr.nl_groups = 0;

    	memset(&nlh, 0, sizeof(nlh));
    	nlh.nlmsg_len = NLMSG_SPACE(MAX_PLOAD);
    	nlh.nlmsg_flags = 0;
    	nlh.nlmsg_type = 0;
    	nlh.nlmsg_seq = 0;
    	nlh.nlmsg_pid = saddr.nl_pid;

    	memcpy(NLMSG_DATA(&nlh), umsg, strlen(umsg));

    	ret = sendto(skfd, &nlh, nlh.nlmsg_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr_nl));
    	if (ret == -1) {
        	freezeit.log("向ReKernel发送消息失败!");
        	close(skfd);
        	exit(-1);
    	}

        while (true) {
           	memset(&u_info, 0, sizeof(u_info));
            len = sizeof(struct sockaddr_nl);
            ret = recvfrom(skfd, &u_info, sizeof(user_msg_info), 0, (struct sockaddr *)&daddr, &len);

            if (ret == -1) {
				freezeit.log("警告:从ReKernel接收消息失败! 将在三秒后重新尝试连接ReKernel!");
                std::this_thread::sleep_for(std::chrono::seconds(3)); 
                continue;
      		}
            const char *ptr = strstr(u_info.msg, "target=");
            if (ptr != nullptr) {
                int uid = atoi(ptr + 7);
				unFreezerTemporary(uid);
            }
			std::this_thread::sleep_for(std::chrono::seconds(10)); 
        }
        close(skfd);
	}

	void cycleThreadFunc() {
		uint32_t halfSecondCnt{ 0 };

		sleep(1);
		getVisibleAppByShell(); // 获取桌面
		BootFreezer();// 开机冻结
		while (true) {
			InotifyMain(cpusetEventPath);
			START_TIME_COUNT;
                if (doze.isScreenOffStandby && doze.checkIfNeedToExit()) {
                    curForegroundApp = std::move(curFgBackup); // recovery
                    updateAppProcess();
                 } else {
					getVisibleAppByLocalSocket();
                    updateAppProcess();
				}
                 
            END_TIME_COUNT;
            
			checkWakeup();// 检查是否有定时解冻
			if (++halfSecondCnt & 1) continue;

			systemTools.cycleCnt++;
			processPendingApp();//1秒一次
            
			// 2分钟一次 在亮屏状态检测是否已经息屏  息屏状态则检测是否再次强制进入深度Doze
			if (doze.checkIfNeedToEnter()) {
				curFgBackup = std::move(curForegroundApp); //backup
				updateAppProcess();
			}

			if (doze.isScreenOffStandby)continue;// 息屏状态 不用执行 以下功能
			BootFreezer();
			if (settings.enableBatteryMonitor == 0) continue;
			systemTools.checkBattery();// 1分钟一次 电池检测
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

			int pid = atoi(file->d_name);
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
	
	// https://cs.android.com/android/platform/superproject/+/master:frameworks/base/services/core/java/com/android/server/am/CachedAppOptimizer.java;l=749
	// https://cs.android.com/android/platform/superproject/+/master:frameworks/base/services/core/jni/com_android_server_am_CachedAppOptimizer.cpp;l=475
	// https://cs.android.com/android/platform/superproject/+/master:frameworks/native/libs/binder/IPCThreadState.cpp;l=1564
	// https://cs.android.com/android/kernel/superproject/+/common-android-mainline:common/drivers/android/binder.c;l=5615
	// https://elixir.bootlin.com/linux/latest/source/drivers/android/binder.c#L5412
	int handleBinder(const vector<int>& pids, const int signal) {
		if (bs.fd <= 0)return 0;

		START_TIME_COUNT;
		struct binder_freeze_info info { 0, static_cast<uint32_t>(signal == SIGSTOP ? 1 : 0), 100 };

		if (SIGSTOP) {
		    for (size_t i = 0; i < pids.size(); i++) {
			    info.pid = pids[i];
			    if (ioctl(bs.fd, BINDER_FREEZE, &info) < 0) {
				    int errorCode = errno;

                    // ret == EAGAIN indicates that transactions have not drained.
                    // Call again to poll for completion.
                        switch (errorCode) {
                        case EAGAIN: // 11
                            break;
                        case EINVAL:  // 22  酷安经常有某进程无法冻结binder
                            break;
                        default:
                            freezeit.logFmt("冻结 Binder 发生异常 [%s] ErrorCode:%d", pids[i], errorCode);
                            break;
                        }

					// 冻结错误，解冻已经被冻结binder的进程
					    info.enable = 0;
					    for (size_t j = 0; j < i; j++) {
						    info.pid = pids[j];
						    ioctl(bs.fd, BINDER_FREEZE, &info); //todo 如果解冻失败？
					    }
					    return -pids[i];
				    }
			    }
		    } else {
			    usleep(1000 * 10);
			    ioctl(bs.fd, BINDER_FREEZE, &info);
		}
		END_TIME_COUNT;
		return 1;
	}

    void binder_close() {
        munmap(bs.mapped, bs.mapSize);
        close(bs.fd);
        bs.fd = -1;
    }

	int binder_open(const char* driver) {
		struct binder_version b_ver { -1 };

		bs.fd = open(driver, O_RDWR | O_CLOEXEC);
		if (bs.fd < 0) {
			freezeit.logFmt("Binder初始化失败 [%s] [%d:%s]", driver, errno, strerror(errno));
			return -1;
		}

		if ((ioctl(bs.fd, BINDER_VERSION, &b_ver) == -1) ||
			(b_ver.protocol_version != BINDER_CURRENT_PROTOCOL_VERSION)) {
			freezeit.logFmt("Binder当前版本: %d,此版本不支持BinderFreezer特性",b_ver.protocol_version);
			close(bs.fd);
			return -1;
		}

		bs.mapped = mmap(NULL, bs.mapSize, PROT_READ, MAP_PRIVATE, bs.fd, 0);
		if (bs.mapped == MAP_FAILED) {
			freezeit.logFmt("Binder mmap失败 [%s] [%d:%s]", driver, errno, strerror(errno));
			close(bs.fd);
			return -1;
		}

		return b_ver.protocol_version;
	} 
};
