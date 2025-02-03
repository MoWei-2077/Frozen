#pragma once

#include "utils.hpp"
#include "vpopen.hpp"

class Freezeit {
private:
	const char* LOG_PATH = "/sdcard/Android/freezeit.log";

	constexpr static int LINE_SIZE = 1024 * 32;   //  32 KiB
	constexpr static int BUFF_SIZE = 1024 * 128;  // 128 KiB

	mutex logPrintMutex;
	bool toFileFlag = false;
	char lineCache[LINE_SIZE] = "[00:00:00]  ";
	char logCache[BUFF_SIZE];
	size_t position = 0;

	string propPath;
	string changelog{ "无" };

	map<string, string> prop{
			{"id",          "Unknown"},
			{"name",        "Unknown"},
			{"version",     "Unknown"},
			{"versionCode", "0"},
			{"author",      "Unknown"},
			{"description", "Unknown"},
	};

	// "Jul 28 2022" --> "2022-07-28"
	const char compilerDate[12] = {
			__DATE__[7],
			__DATE__[8],
			__DATE__[9],
			__DATE__[10],// YYYY year
			'-',

			// First month letter, Oct Nov Dec = '1' otherwise '0'
			(__DATE__[0] == 'O' || __DATE__[0] == 'N' || __DATE__[0] == 'D') ? '1' : '0',

			// Second month letter Jan, Jun or Jul
			(__DATE__[0] == 'J') ? ((__DATE__[1] == 'a') ? '1'
			: ((__DATE__[2] == 'n') ? '6' : '7'))
			: (__DATE__[0] == 'F') ? '2'// Feb
			: (__DATE__[0] == 'M') ? (__DATE__[2] == 'r') ? '3' : '5'// Mar or May
			: (__DATE__[0] == 'A') ? (__DATE__[1] == 'p') ? '4' : '8'// Apr or Aug
			: (__DATE__[0] == 'S') ? '9'// Sep
			: (__DATE__[0] == 'O') ? '0'// Oct
			: (__DATE__[0] == 'N') ? '1'// Nov
			: (__DATE__[0] == 'D') ? '2'// Dec
			: 'X',

			'-',
			__DATE__[4] == ' ' ? '0' : __DATE__[4],// First day letter, replace space with digit
			__DATE__[5],// Second day letter
		'\0',
	};

	void toMem(const char* logStr, const int len) {
		if ((position + len) >= BUFF_SIZE)
			position = 0;

		memcpy(logCache + position, logStr, len);
		position += len;
	}

	void toFile(const char* logStr, const int len) {
		auto fp = fopen(LOG_PATH, "ab");
		if (!fp) {
			fprintf(stderr, "日志输出(追加模式)失败 [%d][%s]", errno, strerror(errno));
			return;
		}

		auto fileSize = ftell(fp);
		if ((fileSize + len) >= BUFF_SIZE) {
			fclose(fp);
			usleep(1000);
			fp = fopen(LOG_PATH, "wb");
			if (!fp) {
				fprintf(stderr, "日志输出(超额清理模式)失败 [%d][%s]", errno, strerror(errno));
				return;
			}
		}

		fwrite(logStr, 1, len, fp);
		fclose(fp);
	}

public:

	int ANDROID_VER = 0;
	int SDK_INT_VER = 0;
	struct _KERNEL_VER {
		int main = 0;
		int sub = 0;
		int patch = 0;
	} kernelVersion;

	string modulePath;
	string moduleEnv{ "Unknown" };
	string workMode{ "Unknown" };
	string kernelVerStr{ "Unknown" };
	string androidVerStr{ "Unknown" };

	uint32_t extMemorySize{ 0 };

	Freezeit& operator=(Freezeit&&) = delete;

	Freezeit(int argc, const string fullPath) {

		modulePath = Utils::parentDir(fullPath);

		int versionCode = -1;
		if (!access("/system/bin/magisk", F_OK)) {
			moduleEnv = "Magisk";
			versionCode = MAGISK::get_version_code();
			if (versionCode <= 0) {
				sleep(2);
				versionCode = MAGISK::get_version_code();
			}
		}
		else if (!access("/data/adb/ksud", F_OK)) {
			moduleEnv = "KernelSU";
			versionCode = KSU::get_version_code();
			if (versionCode <= 0) {
				sleep(2);
				versionCode = KSU::get_version_code();  
			}
		}
		else if (!access("/data/adb/ap/bin/apd", F_OK)) {
			moduleEnv = "Apatch";
			versionCode = Apatch::get_version_code();
			if (versionCode <= 0) {
				sleep(2);
				versionCode = Apatch::get_version_code();
			}
		}
		if (versionCode > 0)
			moduleEnv += " (" + to_string(versionCode) + ")";

		auto fp = fopen((modulePath + "/boot.log").c_str(), "rb");
		if (fp) {
			auto len = fread(logCache, 1, BUFF_SIZE, fp);
			if (len > 0)
				position = len;
			fclose(fp);
		}

		toFileFlag = argc > 1;
		if (toFileFlag) {
			if (position)toFile(logCache, position);
			const char tips[] = "日志已通过文件输出: /sdcard/Android/freezeit.log";
			toMem(tips, sizeof(tips) - 1);
		}

		propPath = modulePath + "/module.prop";
		fp = fopen(propPath.c_str(), "r");
		if (!fp) {
			fprintf(stderr, "找不到模块属性文件 [%s]", propPath.c_str());
			exit(-1);
		}

		char tmp[1024*4];
		while (!feof(fp)) {
			fgets(tmp, sizeof(tmp), fp);
			if (!isalpha(tmp[0])) continue;
			tmp[sizeof(tmp) - 1] = 0;
			auto ptr = strchr(tmp, '=');
			if (!ptr)continue;

			*ptr = 0;
			for (size_t i = (ptr - tmp) + 1; i < sizeof(tmp); i++) {
				if (tmp[i] == '\n' || tmp[i] == '\r') {
					tmp[i] = 0;
					break;
				}
			}
			prop[string(tmp)] = string(ptr + 1);
		}
		fclose(fp);

		changelog = Utils::readString((modulePath + "/changelog.txt").c_str());

		logFmt("模块版本 %s", prop["version"].c_str());
		logFmt("编译时间 %s %s UTC+8", compilerDate, __TIME__);

		fprintf(stderr, "version %s", prop["version"].c_str()); // 发送当前版本信息给监控进程

		ANDROID_VER = __system_property_get("ro.build.version.release", tmp) > 0 ? atoi(tmp) : 0;
		SDK_INT_VER = __system_property_get("ro.build.version.sdk", tmp) > 0 ? atoi(tmp) : 0;
		androidVerStr = to_string(ANDROID_VER) + " (API " + to_string(SDK_INT_VER) + ")";

		utsname kernelInfo{};
		if (!uname(&kernelInfo)) {
			sscanf(kernelInfo.release, "%d.%d.%d", &kernelVersion.main, &kernelVersion.sub,
				&kernelVersion.patch);
			kernelVerStr =
				to_string(kernelVersion.main) + "." + to_string(kernelVersion.sub) + "." +
				to_string(kernelVersion.patch);
		}
	}

	char* getChangelogPtr() { return (char*)changelog.c_str(); }

	size_t getChangelogLen() { return changelog.length(); }


	void setWorkMode(const string& mode) {
		workMode = mode;
	}

	size_t formatProp(char* ptr, const size_t maxSize, const int cpuCluster) {
		return snprintf(ptr, maxSize, "%s\n%s\n%s\n%s\n%s\n%d\n%s\n%s\n%s\n%s\n%u",
			prop["id"].c_str(), prop["name"].c_str(), prop["version"].c_str(),
			prop["versionCode"].c_str(), prop["author"].c_str(),
			cpuCluster, moduleEnv.c_str(), workMode.c_str(),
			androidVerStr.c_str(), kernelVerStr.c_str(), extMemorySize);
	}

	void log(const string& logContent) {
		log(logContent.c_str());
	}
	void formatTime() {
		time_t timeStamp = time(nullptr) + 8 * 3600L;
		int hour = (timeStamp / 3600) % 24;
		int min = (timeStamp % 3600) / 60;
		int sec = timeStamp % 60;

		//lineCache[LINE_SIZE] = "[00:00:00]  ";
		lineCache[1] = (hour / 10) + '0';
		lineCache[2] = (hour % 10) + '0';
		lineCache[4] = (min / 10) + '0';
		lineCache[5] = (min % 10) + '0';
		lineCache[7] = (sec / 10) + '0';
		lineCache[8] = (sec % 10) + '0';

	}
	void log(const char* str) {
		lock_guard<mutex> lock(logPrintMutex);

		formatTime();

		auto len = strlen(str);
		memcpy(lineCache + 11, str, len);
		len += 11;

		lineCache[len++] = '\n';

		if (toFileFlag)
			toFile(lineCache, len);
		else
			toMem(lineCache, len);
	}

	template<typename... Args>
	void logFmt(const char* fmt, Args&&... args) {
		lock_guard<mutex> lock(logPrintMutex);

		formatTime();

		int len = snprintf(lineCache + 11, (size_t)(LINE_SIZE - 11), fmt, std::forward<Args>(args)...) + 11;

		if (len <= 11 || LINE_SIZE <= (len + 1)) {
			lineCache[11] = 0;
			fprintf(stderr, "日志异常: len[%d] lineCache[%s]", len, lineCache);
			return;
		}

		lineCache[len++] = '\n';

		if (toFileFlag)
			toFile(lineCache, len);
		else
			toMem(lineCache, len);
	}

	void clearLog() {
		logCache[0] = '\n';
		position = 1;
	}

	char* getLogPtr() {
		return logCache;
	}

	size_t getLoglen() {
		return position;
	}
};
