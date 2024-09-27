// Freezeit 冻它模块  By JARK006

#include "freezeit.hpp"
#include "settings.hpp"
#include "managedApp.hpp"
#include "systemTools.hpp"
#include "doze.hpp"
#include "freezer.hpp"
#include "server.hpp"

int main(int argc, char **argv) {
    //先获取模块当前目录，Init()开启守护线程后, 工作目录将切换到根目录 "/"
    char fullPath[1024] = {};
    auto pathPtr = realpath(argv[0], fullPath); 

    Utils::Init();

    Freezeit freezeit(argc, string(pathPtr));
    Settings settings(freezeit);
    SystemTools systemTools(freezeit, settings);
    ManagedApp managedApp(freezeit, settings);
    Doze doze(freezeit, settings, managedApp, systemTools);
    Freezer freezer(freezeit, settings, managedApp, systemTools, doze);
    Server server(freezeit, settings, managedApp, systemTools, doze, freezer);

    sleep(3600 * 24 * 365);//放年假
    return 0;
}

/*
TODO

1. 识别状态栏播放控件为前台 参考开源APP listen1 lxmusic
2. 进程冻结状态整合
3. 一些应用解冻后无法进入下一个activity
4. QQ解冻无网络

5. 抖音短时间解冻后重载：上次正在看的视频没了
6. 偶尔亮屏后，系统手势(返回，主页，最近任务)控制失灵，约3-5秒后恢复
*/

