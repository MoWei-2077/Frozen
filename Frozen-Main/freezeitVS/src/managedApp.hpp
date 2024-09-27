#pragma once

#include "utils.hpp"
#include "freezeit.hpp"
#include "settings.hpp"
#include "vpopen.hpp"


class ManagedApp {
private:
    string cfgPath;
    string labelPath;

    Freezeit& freezeit;
    Settings& settings;

    static const size_t PACKAGE_LIST_BUF_SIZE = 256 * 1024;
    unique_ptr<char[]> packageListBuff;

    string homePackage;
    map<string, int> uidIndex;
    map<int, cfgStruct> cfgTemp;

    const unordered_set<string> whiteListForce{
            "com.xiaomi.mibrain.speech",            // 系统语音引擎
            "com.xiaomi.scanner",                   // 小爱视觉
            "com.xiaomi.xmsf",                      // Push
            "com.xiaomi.xmsfkeeper",                // Push
            "com.xiaomi.misettings",                // 设置
            "com.xiaomi.barrage",                   // 弹幕通知
            "com xiaomi.aireco",                    // 小爱建议
            "com.xiaomi.account",                   // 小米账号
            "com.miui.notes",                       // 笔记  冻结会导致系统侧边栏卡住
            "com.miui.calculator",                  // 计算器
            "com.miui.compass",                     // 指南针
            "com.miui.mediaeditor",                 // 相册编辑
            "com.miui.personalassistant",           // 个人助理
            "com.miui.vipservice",                  // 我的服务
            "com.miui.systemAdSolution",            // 智能助理 广告相关 冻结会导致酷安等应用卡顿
            "com.miui.home",
            "com.miui.carlink",
            "com.miui.packageinstaller",            // 安装包管理
            "com.miui.accessibility",               // 小米无障碍
            "com.miui.core",                        // MIUI SDK
            "com.miui.privacycomputing",            // MIUI Privacy Components
            "com.miui.securityadd",                 // 系统服务组件
            "com.miui.securityinputmethod",         // 小米安全键盘
            "com.miui.system",
            "com.miui.vpnsdkmanager",               // MiuiVpnSdkManager
            "com.mfashiongallery.emag",             // 小米画报
            "com.huawei.hwid",                      // HMS core服务

            "cn.litiaotiao.app",                    // 李跳跳
            "com.litiaotiao.app",                   // 李跳跳
            "hello.litiaotiao.app",                 // 李跳跳
            "com.zfdang.touchhelper",               // 跳广告
            "com.giftedcat.adskiphelper",           // 跳广告
            "com.merxury.blocker",                  // Blocker
            "com.wpengapp.lightstart",              // 轻启动
            "li.songe.gkd",                         // GKD
            "com.sevtinge.hyperceiler",             // HyperCeiler

            "com.topjohnwu.magisk",                 // Magisk
            "org.lsposed.manager",                  // LSPosed
            "name.monwf.customiuizer",              // 米客 原版
            "name.mikanoshi.customiuizer",          // 米客
            "com.android.vending",                  // Play 商店

            "org.meowcat.xposed.mipush",            // 小米推送框架增强
            "top.trumeet.mipush",                   // 小米推送服务
            "one.yufz.hmspush",                     // HMSPush服务

            "app.lawnchair",                        // Lawnchair
            "com.microsoft.launcher",               // 微软桌面
            "com.teslacoilsw.launcher",             // Nova Launcher
            "com.hola.launcher",                    // Hola桌面
            "com.transsion.XOSLauncher",            // XOS桌面
            "com.mi.android.globallauncher",        // POCO桌面
            "com.gau.go.launcherex",                // GO桌面
            "bitpit.launcher",                      // Niagara Launcher
            "com.google.android.apps.nexuslauncher",// pixel 桌面
            "com.oppo.launcher",

            "me.weishu.kernelsu",                   // KernelSU
            "top.canyie.dreamland.manager",         // Dreamland
            "com.coloros.packageinstaller",         // 安装包管理
            "com.oplus.packageinstaller",           // 安装包管理
            "com.iqoo.packageinstaller",            // 安装包管理
            "com.vivo.packageinstaller",            // 安装包管理
            "com.google.android.packageinstaller",  // 软件包安装程序


            "com.baidu.input",                            //百度输入法
            "com.baidu.input_huawei",                     //百度输入法华为版
            "com.baidu.input_mi",                         //百度输入法小米版
            "com.baidu.input_oppo",                       //百度输入法OPPO版
            "com.baidu.input_vivo",                       //百度输入法VIVO版
            "com.baidu.input_yijia",                      //百度输入法一加版

            "com.sohu.inputmethod.sogou",                 //搜狗输入法
            "com.sohu.inputmethod.sogou.xiaomi",          //搜狗输入法小米版
            "com.sohu.inputmethod.sogou.meizu",           //搜狗输入法魅族版
            "com.sohu.inputmethod.sogou.nubia",           //搜狗输入法nubia版
            "com.sohu.inputmethod.sogou.chuizi",          //搜狗输入法chuizi版
            "com.sohu.inputmethod.sogou.moto",            //搜狗输入法moto版
            "com.sohu.inputmethod.sogou.zte",             //搜狗输入法中兴版
            "com.sohu.inputmethod.sogou.samsung",         //搜狗输入法samsung版
            "com.sohu.input_yijia",                       //搜狗输入法一加版

            "com.iflytek.inputmethod",                    //讯飞输入法
            "com.iflytek.inputmethod.miui",               //讯飞输入法小米版
            "com.iflytek.inputmethod.googleplay",         //讯飞输入法googleplay版
            "com.iflytek.inputmethod.smartisan",          //讯飞输入法smartisan版
            "com.iflytek.inputmethod.oppo",               //讯飞输入法oppo版
            "com.iflytek.inputmethod.oem",                //讯飞输入法oem版
            "com.iflytek.inputmethod.custom",             //讯飞输入法custom版
            "com.iflytek.inputmethod.blackshark",         //讯飞输入法blackshark版
            "com.iflytek.inputmethod.zte",                //讯飞输入法zte版

            "com.tencent.qqpinyin",                       // QQ拼音输入法
            "com.google.android.inputmethod.latin",       //谷歌Gboard输入法
            "com.touchtype.swiftkey",                     //微软swiftkey输入法
            "com.touchtype.swiftkey.beta",                //微软swiftkeyBeta输入法
            "im.weshine.keyboard",                        // KK键盘输入法
            "com.komoxo.octopusime",                      //章鱼输入法
            "com.qujianpan.duoduo",                       //见萌输入法
            "com.lxlm.lhl.softkeyboard",                  //流行输入法
            "com.jinkey.unfoldedime",                     //不折叠输入法
            "com.iflytek.inputmethods.DungkarIME",        //东噶藏文输入法
            "com.oyun.qingcheng",                         //奥云蒙古文输入法
            "com.ziipin.softkeyboard",                    // Badam维语输入法
            "com.kongzue.secretinput",                    // 密码键盘


            "com.google.android.ext.services",
            "com.google.android.ext.shared",
            "com.google.android.gms",               // GMS 服务
            "com.google.android.gsf",               // Google 服务框架

            "com.google.android.systemui.gxoverlay",    // SystemUIGX
            "com.google.android.tag",    // Tags
            "com.google.android.documentsui",    // 文件
            "com.google.android.ext.shared",    // Android Shared Library
            "com.google.android.captiveportallogin",    // 强制门户登录
            "com.google.android.printservice.recommendation",    // Print Service Recommendation Service
            "com.google.android.gms.supervision",    // Family Link 家长控制
            "com.google.android.as.oss",    // Private Compute Services
            "com.google.android.configupdater",    // ConfigUpdater
            "com.google.android.apps.restore",    // 数据恢复工具
            "com.google.android.onetimeinitializer",    // Google One Time Init
            "com.google.android.odad",    // Google Play 保护机制服务
            "com.google.android.settings.intelligence",    // 设置小助手
            "com.google.android.partnersetup",    // Google Partner Setup
            "com.google.android.projection.gearhead",    // Android Auto
            "com.google.android.apps.wellbeing",    // 数字健康
            "com.google.android.as",    // Android System Intelligence
            "com.google.android.dialer",    // 电话
            "com.google.android.apps.messaging",    // 信息
            "com.google.android.googlequicksearchbox",    // Google
            "com.google.android.webview",    // Android System WebView
            "com.google.android.tts",    // Google 语音服务
            "com.google.android.deskclock",    // 时钟
            "com.google.android.markup",    // Markup
            "com.google.android.calendar",    // 日历
            "com.google.android.soundpicker",    // 音效
            "com.google.android.apps.wallpaper.nexus",    // Google Wallpaper Images
            "com.google.android.modulemetadata",    // Main components
            "com.google.android.contacts",    // 通讯录
            "com.google.android.apps.customization.pixel",    // Pixel Themes
            "com.google.android.apps.photos",    // 相册
            "com.google.android.feedback",    // 应用商店反馈代理程序
            "com.google.android.apps.wallpaper",    // 壁纸与个性化
            "com.google.android.ext.services",    // Android Services Library
            "com.google.android.providers.media.module",    // 媒体
            "com.google.android.wifi.resources",    // 系统 WLAN 资源
            "com.google.android.hotspot2.osulogin",    // OsuLogin
            "com.google.android.safetycenter.resources",    // Google 安全中心资源
            "com.google.android.permissioncontroller",    // 权限控制器
            "com.google.android.ondevicepersonalization.services",    // 
            "com.google.android.adservices.api",    // Android 系统
            "com.google.android.devicelockcontroller",    // DeviceLockController
            "com.google.android.connectivity.resources",    // 系统网络连接资源
            "com.google.android.healthconnect.controller",    // Health Connect
            "com.google.android.cellbroadcastreceiver",    // 无线紧急警报
            "com.google.android.uwb.resources",    // System UWB Resources
            "com.google.android.rkpdapp",    // RemoteProvisioner


            "com.android.launcher",
            "com.android.launcher2",
            "com.android.launcher3",
            "com.android.launcher4",
            "com.android.camera",
            "com.android.camera2",
            "com.android.apps.tag", // Tags
            "com.android.bips", // 系统打印服务
            "com.android.bluetoothmidiservice", // Bluetooth MIDI Service
            "com.android.cameraextensions", // CameraExtensionsProxy
            "com.android.captiveportallogin", // CaptivePortalLogin
            "com.android.carrierdefaultapp", // 运营商默认应用
            "com.android.certinstaller", // 证书安装程序
            "com.android.companiondevicemanager", // 配套设备管理器
            "com.android.connectivity.resources", // 系统网络连接资源
            "com.android.contacts", // 通讯录与拨号
            "com.android.deskclock", // 时钟
            "com.android.dreams.basic", // 基本互动屏保
            "com.android.egg", // Android S Easter Egg
            "com.android.emergency", // 急救信息
            "com.android.externalstorage", // 外部存储设备
            "com.android.hotspot2.osulogin", // OsuLogin
            "com.android.htmlviewer", // HTML 查看器
            "com.android.incallui", // 电话
            "com.android.internal.display.cutout.emulation.corner", // 边角刘海屏
            "com.android.internal.display.cutout.emulation.double", // 双刘海屏
            "com.android.internal.display.cutout.emulation.hole", // 打孔屏
            "com.android.internal.display.cutout.emulation.tall", // 长型刘海屏
            "com.android.internal.display.cutout.emulation.waterfall", // 瀑布刘海屏
            "com.android.internal.systemui.navbar.gestural", // Gestural Navigation Bar
            "com.android.internal.systemui.navbar.gestural_extra_wide_back", // Gestural Navigation Bar
            "com.android.internal.systemui.navbar.gestural_narrow_back", // Gestural Navigation Bar
            "com.android.internal.systemui.navbar.gestural_wide_back", // Gestural Navigation Bar
            "com.android.internal.systemui.navbar.threebutton", // 3 Button Navigation Bar
            "com.android.managedprovisioning", // 工作设置
            "com.android.mms", // 短信
            "com.android.modulemetadata", // Module Metadata
            "com.android.mtp", // MTP 主机
            "com.android.musicfx", // MusicFX
            "com.android.networkstack.inprocess.overlay", // NetworkStackInProcessResOverlay
            "com.android.networkstack.overlay", // NetworkStackOverlay
            "com.android.networkstack.tethering.inprocess.overlay", // TetheringResOverlay
            "com.android.networkstack.tethering.overlay", // TetheringResOverlay
            "com.android.packageinstaller", // 软件包安装程序
            "com.android.pacprocessor", // PacProcessor
            "com.android.permissioncontroller", // 权限控制器
            "com.android.printspooler", // 打印处理服务
            "com.android.providers.calendar", // 日历存储
            "com.android.providers.contacts", // 联系人存储
            "com.android.providers.downloads.ui", // 下载管理
            "com.android.providers.media.module", // 媒体存储设备
            "com.android.proxyhandler", // ProxyHandler
            "com.android.server.telecom.overlay.miui", // 通话管理
            "com.android.settings.intelligence", // 设置建议
            "com.android.simappdialog", // Sim App Dialog
            "com.android.soundrecorder", // 录音机
            "com.android.statementservice", // 意图过滤器验证服务
            "com.android.storagemanager", // 存储空间管理器
            "com.android.theme.font.notoserifsource", // Noto Serif / Source Sans Pro
            "com.android.traceur", // 系统跟踪
            "com.android.uwb.resources", // System UWB Resources
            "com.android.vpndialogs", // VpnDialogs
            "com.android.wallpaper.livepicker", // Live Wallpaper Picker
            "com.android.wifi.resources", // 系统 WLAN 资源
            "com.debug.loggerui", // DebugLoggerUI
            "com.fingerprints.sensortesttool", // Sensor Test Tool
            "com.lbe.security.miui", // 权限管理服务
            "com.mediatek.callrecorder", // 通话录音机
            "com.mediatek.duraspeed", // 快霸
            "com.mediatek.engineermode", // EngineerMode
            "com.mediatek.lbs.em2.ui", // LocationEM2
            "com.mediatek.location.mtkgeofence", // Mtk Geofence
            "com.mediatek.mdmconfig", // MDMConfig
            "com.mediatek.mdmlsample", // MDMLSample
            "com.mediatek.miravision.ui", // MiraVision
            "com.mediatek.op01.telecom", // OP01Telecom
            "com.mediatek.op09clib.phone.plugin", // OP09ClibTeleService
            "com.mediatek.op09clib.telecom", // OP09ClibTelecom
            "com.mediatek.ygps", // YGPS
            "com.tencent.soter.soterserver", // SoterService
            "com.unionpay.tsmservice.mi", // 银联可信服务安全组件小米版本


            "android.ext.services", // Android Services Library
            "android.ext.shared", // Android Shared Library
            "com.android.adservices.api", // Android AdServices
            "com.android.bookmarkprovider", // Bookmark Provider
            "com.android.cellbroadcastreceiver.module", // 无线紧急警报
            "com.android.dialer", // 电话
            "com.android.dreams.phototable", // 照片屏幕保护程序
            "com.android.inputmethod.latin", // Android 键盘 (AOSP)
            "com.android.intentresolver", // IntentResolver
            "com.android.internal.display.cutout.emulation.noCutout", // 隐藏
            "com.android.internal.systemui.navbar.twobutton", // 2 Button Navigation Bar
            "com.android.messaging", // 短信
            "com.android.onetimeinitializer", // One Time Init
            "com.android.printservice.recommendation", // Print Service Recommendation Service
            "com.android.safetycenter.resources", // 安全中心资源
            "com.android.soundpicker", // 声音
            "com.android.systemui", // 系统界面
            "com.android.wallpaper", // 壁纸和样式
            "com.qualcomm.qti.cne", // CneApp
            "com.qualcomm.qti.poweroffalarm", // 关机闹钟
            "com.qualcomm.wfd.service", // Wfd Service
            "org.lineageos.aperture", // 相机
            "org.lineageos.audiofx", // AudioFX
            "org.lineageos.backgrounds", // 壁纸
            "org.lineageos.customization", // Lineage Themes
            "org.lineageos.eleven", // 音乐
            "org.lineageos.etar", // 日历
            "org.lineageos.jelly", // 浏览器
            "org.lineageos.overlay.customization.blacktheme", // Black theme
            "org.lineageos.overlay.font.lato", // Lato
            "org.lineageos.overlay.font.rubik", // Rubik
            "org.lineageos.profiles", // 情景模式信任提供器
            "org.lineageos.recorder", // 录音机
            "org.lineageos.updater", // 系统更新
            "org.protonaosp.deviceconfig", // Simple Device Configuration

            "android.aosp.overlay",
            "android.miui.home.launcher.res",
            "android.miui.overlay",
            "com.android.carrierconfig",
            "com.android.carrierconfig.overlay.miui",
            "com.android.incallui.overlay",
            "com.android.managedprovisioning.overlay",
            "com.android.ondevicepersonalization.services",
            "com.android.overlay.cngmstelecomm",
            "com.android.overlay.gmscontactprovider",
            "com.android.overlay.gmssettingprovider",
            "com.android.overlay.gmssettings",
            "com.android.overlay.gmstelecomm",
            "com.android.overlay.gmstelephony",
            "com.android.overlay.systemui",
            "com.android.phone.overlay.miui",
            "com.android.providers.settings.overlay",
            "com.android.sdksandbox",
            "com.android.settings.overlay.miui",
            "com.android.stk.overlay.miui",
            "com.android.systemui.gesture.line.overlay",
            "com.android.systemui.navigation.bar.overlay",
            "com.android.systemui.overlay.miui",
            "com.android.wallpapercropper",
            "com.android.wallpaperpicker",
            "com.android.wifi.dialog",
            "com.android.wifi.resources.overlay",
            "com.android.wifi.resources.xiaomi",
            "com.android.wifi.system.mainline.resources.overlay",
            "com.android.wifi.system.resources.overlay",
            "com.google.android.cellbroadcastreceiver.overlay.miui",
            "com.google.android.cellbroadcastservice.overlay.miui",
            "com.google.android.overlay.gmsconfig",
            "com.google.android.overlay.modules.ext.services",
            "com.google.android.trichromelibrary_511209734",
            "com.google.android.trichromelibrary_541411734",
            "com.mediatek.FrameworkResOverlayExt",
            "com.mediatek.SettingsProviderResOverlay",
            "com.mediatek.batterywarning",
            "com.mediatek.cellbroadcastuiresoverlay",
            "com.mediatek.frameworkresoverlay",
            "com.mediatek.gbaservice",
            "com.mediatek.voiceunlock",
            "com.miui.core.internal.services",
            "com.miui.face.overlay.miui",
            "com.miui.miwallpaper.overlay.customize",
            "com.miui.miwallpaper.wallpaperoverlay.config.overlay",
            "com.miui.rom",
            "com.miui.settings.rro.device.config.overlay",
            "com.miui.settings.rro.device.hide.statusbar.overlay",
            "com.miui.settings.rro.device.type.overlay",
            "com.miui.system.overlay",
            "com.miui.systemui.carriers.overlay",
            "com.miui.systemui.devices.overlay",
            "com.miui.systemui.overlay.devices.android",
            "com.miui.translation.kingsoft",
            "com.miui.translation.xmcloud",
            "com.miui.translationservice",
            "com.miui.voiceassistoverlay",
            "com.miui.wallpaper.overlay.customize",
            "com.xiaomi.bluetooth.rro.device.config.overlay",


            "android.auto_generated_rro_product__",
            "android.auto_generated_rro_vendor__",
            "com.android.backupconfirm",
            "com.android.carrierconfig.auto_generated_rro_vendor__",
            "com.android.cts.ctsshim",
            "com.android.cts.priv.ctsshim",
            "com.android.documentsui.auto_generated_rro_product__",
            "com.android.emergency.auto_generated_rro_product__",
            "com.android.imsserviceentitlement",
            "com.android.imsserviceentitlement.auto_generated_rro_product__",
            "com.android.inputmethod.latin.auto_generated_rro_product__",
            "com.android.launcher3.overlay",
            "com.android.managedprovisioning.auto_generated_rro_product__",
            "com.android.nearby.halfsheet",
            "com.android.phone.auto_generated_rro_vendor__",
            "com.android.providers.settings.auto_generated_rro_product__",
            "com.android.providers.settings.auto_generated_rro_vendor__",
            "com.android.settings.auto_generated_rro_product__",
            "com.android.sharedstoragebackup",
            "com.android.smspush",
            "com.android.storagemanager.auto_generated_rro_product__",
            "com.android.systemui.auto_generated_rro_product__",
            "com.android.systemui.auto_generated_rro_vendor__",
            "com.android.systemui.plugin.globalactions.wallet",
            "com.android.wallpaper.auto_generated_rro_product__",
            "com.android.wifi.resources.oneplus_sdm845",
            "com.qualcomm.timeservice",
            "lineageos.platform.auto_generated_rro_product__",
            "lineageos.platform.auto_generated_rro_vendor__",
            "org.codeaurora.ims",
            "org.lineageos.aperture.auto_generated_rro_vendor__",
            "org.lineageos.lineageparts.auto_generated_rro_product__",
            "org.lineageos.lineagesettings.auto_generated_rro_product__",
            "org.lineageos.lineagesettings.auto_generated_rro_vendor__",
            "org.lineageos.overlay.customization.navbar.nohint",
            "org.lineageos.settings.device.auto_generated_rro_product__",
            "org.lineageos.settings.doze.auto_generated_rro_product__",
            "org.lineageos.settings.doze.auto_generated_rro_vendor__",
            "org.lineageos.setupwizard.auto_generated_rro_product__",
            "org.lineageos.updater.auto_generated_rro_product__",
            "org.protonaosp.deviceconfig.auto_generated_rro_product__",

    };

    const unordered_set<string> whiteListDefault{
        "com.mi.health",                        // 小米运动健康
        "com.tencent.mm.wxa.sce",               // 微信小程序   三星OneUI专用

        "com.onlyone.onlyonestarter",           // 三星系应用
        "com.samsung.accessory.neobeanmgr",     // Galaxy Buds Live Manager
        "com.samsung.app.newtrim",              // 编辑器精简版
        "com.diotek.sec.lookup.dictionary",     // 字典
    };

public:

    const set<FREEZE_MODE> FREEZE_MODE_SET{
            FREEZE_MODE::TERMINATE,
            FREEZE_MODE::SIGNAL,
            FREEZE_MODE::SIGNAL_BREAK,
            FREEZE_MODE::FREEZER,
            FREEZE_MODE::FREEZER_BREAK,
            FREEZE_MODE::WHITELIST,
            FREEZE_MODE::WHITEFORCE,
    };

    ManagedApp& operator=(ManagedApp&&) = delete;

    ManagedApp(Freezeit& freezeit, Settings& settings) : freezeit(freezeit), settings(settings) {
        cfgPath = freezeit.modulePath + "/appcfg.txt";
        labelPath = freezeit.modulePath + "/applabel.txt";

        packageListBuff = make_unique<char[]>(PACKAGE_LIST_BUF_SIZE);

        updateAppList();
        loadLabelFile();

        loadConfigFile2CfgTemp();
        updateIME2CfgTemp();
        applyCfgTemp();
        update2xposedByLocalSocket();
    }

    const static int UID_START = 10000;
    const static int UID_END = 14000;
    const static int appMaxNum = UID_END - UID_START;
    appInfoStruct appInfoMap[appMaxNum];

    auto& operator[](const int uid) { return appInfoMap[uid - UID_START]; }
    auto& operator[](const string& package) { return appInfoMap[uidIndex[package] - UID_START]; }

    void clear() { for (auto& appInfo : appInfoMap) appInfo.uid = -1; }

    bool contains(const int uid) const { return UID_START <= uid && uid < UID_END && appInfoMap[uid - UID_START].uid == uid; }

    bool contains(const string& package) const { return uidIndex.contains(package); }

    bool isBlackList(const int uid) { return contains(uid) && appInfoMap[uid - UID_START].isBlacklist(); }

    auto& getLabel(const int uid) { return appInfoMap[uid - UID_START].label; }

    int getUid(const string& package) { return uidIndex[package]; }

    int getUidOrDefault(const string& package, const int defaultValue) {
        auto it = uidIndex.find(package);
        return it != uidIndex.end() ? it->second : defaultValue;
    }

    bool hasHomePackage() const { return homePackage.length() > 2; }

    void updateHomePackage(const string& package) {
        homePackage = package;
        const auto& it = uidIndex.find(package);
        if (it == uidIndex.end()) {
            freezeit.logFmt("当前桌面信息异常，建议反馈: [%s]", package.c_str());
            return;
        }

        const int uid = it->second;
        appInfoMap[uid - UID_START].freezeMode = FREEZE_MODE::WHITEFORCE;
    }

    bool readPackagesListA12(map<int, string>& _allAppList, map<int, string>& _thirdAppList) {
        START_TIME_COUNT;

        stringstream ss;
        ss << ifstream("/data/system/packages.list").rdbuf();

        string_view sysEnd("@system");
        string line;
        while (getline(ss, line)) {
            if (line.length() < 10) continue;
            if (line.starts_with("com.google.android.trichromelibrary")) continue;

            int uid;
            char package[256] = {};
            sscanf(line.c_str(), "%s %d", package, &uid);
            if (uid < UID_START || UID_END <= uid) continue;

            const string& packageName{ package };
            _allAppList[uid] = packageName;
            if (!line.ends_with(sysEnd))
                _thirdAppList[uid] = packageName;
        }
        END_TIME_COUNT;
        return _allAppList.size() > 0;
    }

    bool readPackagesListA10_11(map<int, string>& _allAppList) {
        START_TIME_COUNT;

        stringstream ss;
        ss << ifstream("/data/system/packages.list").rdbuf();

        string line;
        while (getline(ss, line)) {
            if (line.length() < 10) continue;
            if (line.starts_with("com.google.android.trichromelibrary")) continue;

            int uid;
            char package[256] = {};
            sscanf(line.c_str(), "%s %d", package, &uid);
            if (uid < UID_START || UID_END <= uid) continue;

            _allAppList[uid] = package;
        }
        END_TIME_COUNT;
        return _allAppList.size() > 0;
    }

    void readCmdPackagesAll(map<int, string>& _allAppList) {
        START_TIME_COUNT;
        stringstream ss;
        string line;

        const char* cmdList[] = { "/system/bin/cmd", "cmd", "package", "list", "packages", "-U",
                                 nullptr };
        VPOPEN::vpopen(cmdList[0], cmdList + 1, packageListBuff.get(), PACKAGE_LIST_BUF_SIZE);
        ss << packageListBuff.get();
        while (getline(ss, line)) {
            // package:com.google.android.GoogleCameraGood uid:10364
            if (!Utils::startWith("package:", line.c_str()))continue;
            auto idx = line.find(" uid:");
            if (idx == string::npos)continue;
            int uid = atoi(line.c_str() + idx + 5);

            if (idx < 10 || uid < UID_START || UID_END <= uid) continue;
            _allAppList[uid] = line.substr(8, idx - 8); //package
        }
        END_TIME_COUNT;
    }

    void readCmdPackagesThird(map<int, string>& _thirdAppList) {
        START_TIME_COUNT;
        stringstream ss;
        string line;

        const char* cmdList[] = { "/system/bin/cmd", "cmd", "package", "list", "packages", "-3",
                                 "-U", nullptr };
        VPOPEN::vpopen(cmdList[0], cmdList + 1, packageListBuff.get(), PACKAGE_LIST_BUF_SIZE);
        ss << packageListBuff.get();
        while (getline(ss, line)) {
            // package:com.google.android.GoogleCameraGood uid:10364
            if (!Utils::startWith("package:", line.c_str()))continue;
            auto idx = line.find(" uid:");
            if (idx == string::npos)continue;
            int uid = atoi(line.c_str() + idx + 5);

            if (idx < 10 || uid < UID_START || UID_END <= uid) continue;
            _thirdAppList[uid] = line.substr(8, idx - 8); //package
        }
        END_TIME_COUNT;
    }

    // 开机，更新冻结配置，更新应用名称，都会调用
    void updateAppList() {
        START_TIME_COUNT;

        map<int, string> allAppList, thirdAppList;

        if (!readPackagesListA12(allAppList, thirdAppList)) {
            readCmdPackagesAll(allAppList);
            readCmdPackagesThird(thirdAppList);
        }

        if (allAppList.size() == 0) {
            freezeit.log("没有应用或获取失败");
            return;
        }
        else {
            freezeit.logFmt("更新应用 %lu  系统:%lu 三方:%lu",
                allAppList.size(), allAppList.size() - thirdAppList.size(),
                thirdAppList.size());
        }

        uidIndex.clear();
        for (const auto& [uid, package] : allAppList) {
            uidIndex[package] = uid;        // 更新 按包名取UID
            if (contains(uid))continue;

            const bool isSYS = !thirdAppList.contains(uid);
            appInfoMap[uid - UID_START] = appInfoStruct{
                .uid = uid,
                .freezeMode = isSYS ? FREEZE_MODE::WHITELIST : FREEZE_MODE::FREEZER,
                .isPermissive = true,
                .delayCnt = 0,
                .timelineUnfrozenIdx = -1,
                .isSystemApp = isSYS,
                .startTimestamp = 0,
                .stopTimestamp = 0,
                .totalRunningTime = 0,
                .package = package,
                .label = package,
                .pids = {},
            };
        }
        // 移除已卸载应用
        for (auto& appInfo : appInfoMap) {
            if (appInfo.uid < UID_START || allAppList.contains(appInfo.uid))continue;

            appInfo.uid = -1;
            appInfo.package.clear();
            appInfo.label.clear();
            appInfo.pids.clear();
        }
        END_TIME_COUNT;
    }

    void loadConfigFile2CfgTemp() {
        cfgTemp.clear();

        ifstream file(cfgPath);
        if (!file.is_open())
            return;

        string line;
        while (getline(file, line)) {
            if (line.length() <= 4) {
                freezeit.logFmt("A配置错误: [%s]", line.c_str());
                continue;
            }

            auto value = Utils::splitString(line, " ");
            if (value.size() != 3 || value[0].empty()) {
                freezeit.logFmt("B配置错误: [%s]", line.c_str());
                continue;
            }

            int uid;
            if (isdigit(value[0][0])) {
                uid = atoi(value[0].c_str());
            }
            else {
                auto it = uidIndex.find(value[0]);
                if (it == uidIndex.end())continue;
                uid = it->second;
            }

            const FREEZE_MODE freezeMode = static_cast<FREEZE_MODE>(atoi(value[1].c_str()));
            if (!FREEZE_MODE_SET.contains(freezeMode)) {
                freezeit.logFmt("C配置错误: [%s]", line.c_str());
                continue;
            }

            const bool isPermissive = atoi(value[2].c_str()) != 0;
            cfgTemp[uid] = { freezeMode, isPermissive };
        }
        file.close();
    }

    void loadConfig2CfgTemp(map<int, cfgStruct>& newCfg) {
        cfgTemp = std::move(newCfg);
    }

    void updateIME2CfgTemp() {
        const char* cmdList[] = { "/system/bin/ime", "ime", "list", "-s", nullptr };
        char buf[1024 * 4];
        VPOPEN::vpopen(cmdList[0], cmdList + 1, buf, sizeof(buf));

        stringstream ss;
        ss << buf;

        string line;
        while (getline(ss, line)) {

            auto idx = line.find_first_of('/');
            if (idx == string::npos) continue;

            const string& package = line.substr(0, idx);
            if (package.length() < 6) continue;

            auto it = uidIndex.find(package);
            if (it == uidIndex.end()) continue;

            cfgTemp[it->second] = { FREEZE_MODE::WHITEFORCE, 0 };
        }
    }

    bool isSystemApp(const char* ptr) {
        const char* prefix[] = {
                "com.miui.",
                "com.oplus.",
                "com.coloros.",
                "com.heytap.",
                "com.samsung.android.",
                "com.samsung.systemui.",
                "com.android.samsung.",
                "com.sec.android.",
        };
        for (size_t i = 0; i < sizeof(prefix) / sizeof(prefix[0]); i++) {
            if (Utils::startWith(prefix[i], ptr))
                return true;
        }
        return false;
    }

    bool isTrustedApp(const char* ptr) {
        const char* prefix[] = {
                "com.github.",
                "io.github.",
        };
        for (size_t i = 0; i < sizeof(prefix) / sizeof(prefix[0]); i++) {
            if (Utils::startWith(prefix[i], ptr))
                return true;
        }
        return false;
    }

    void applyCfgTemp() {
        for (auto& appInfo : appInfoMap) {
            if (appInfo.uid < UID_START)continue;

            if (isSystemApp(appInfo.package.c_str()) || whiteListDefault.contains(appInfo.package))
                appInfo.freezeMode = FREEZE_MODE::WHITELIST;
        }

        for (const auto& [uid, cfg] : cfgTemp) {
            if (contains(uid)) {
                auto& appInfo = appInfoMap[uid - UID_START];
                appInfo.freezeMode = cfg.freezeMode;
                appInfo.isPermissive = cfg.isPermissive;
            }
        }

        for (auto& appInfo : appInfoMap) {
            if (appInfo.uid < UID_START)continue;

            if (isTrustedApp(appInfo.package.c_str()) || whiteListForce.contains(appInfo.package))
                appInfo.freezeMode = FREEZE_MODE::WHITEFORCE;
        }

        if (homePackage.length() > 3) {
            auto it = uidIndex.find(homePackage);
            if (it != uidIndex.end())
                appInfoMap[it->second - UID_START].freezeMode = FREEZE_MODE::WHITEFORCE;
        }
    }

    void saveConfig() {
        string tmp;
        tmp.reserve(1024UL * 128);
        for (const auto& appInfo : appInfoMap) {
            if (appInfo.uid < UID_START)continue;

            if (appInfo.freezeMode < FREEZE_MODE::WHITEFORCE) {
                tmp += appInfo.package;
                tmp += " ";
                tmp += to_string(static_cast<int>(appInfo.freezeMode));
                tmp += " ";
                tmp += to_string(appInfo.isPermissive ? 1 : 0);
                tmp += "\n";
            }
        }

        freezeit.log(Utils::writeString(cfgPath.c_str(), tmp.c_str(), tmp.length()) ?
            "配置保存成功" : "⚠️配置保存失败⚠️");
    }

    void update2xposedByLocalSocket() {
        string tmp;
        tmp.reserve(1024L * 16);

        for (int i = 0; i < 40; i++) {
            tmp += to_string(settings[i]);
            tmp += ' ';
        }
        tmp += '\n';

        vector<int> permissiveUids;
        for (const auto& appInfo : appInfoMap) {
            if (appInfo.uid < UID_START)continue;

            if (appInfo.isWhitelist()) continue;

            tmp += to_string(appInfo.uid);
            tmp += appInfo.package;
            tmp += ' ';

            if (appInfo.isPermissive)
                permissiveUids.emplace_back(appInfo.uid);
        }
        tmp += '\n';

        for (const int uid : permissiveUids) {
            tmp += to_string(uid);
            tmp += ' ';
        }
        tmp += '\n';

        for (int i = 0; i < 3; i++) {
            int buff[8];
            const int recvLen = Utils::localSocketRequest(XPOSED_CMD::SET_CONFIG, tmp.c_str(),
                tmp.length(), buff, sizeof(buff));

            if (recvLen != 4) {
                freezeit.logFmt("%s() 更新到Xposed 第%d次异常 sendLen[%lu] recvLen[%d] %d:%s",
                    __FUNCTION__, i + 1, tmp.length(), recvLen, errno, strerror(errno));

                if (0 < recvLen && recvLen < static_cast<int>(sizeof(buff)))
                    freezeit.logFmt("DumpHex: [%s]", Utils::bin2Hex(buff, recvLen).c_str());

                sleep(1);
                continue;
            }

            switch (static_cast<REPLY>(buff[0])) {
            case REPLY::SUCCESS:
                return;
            case REPLY::FAILURE:
                freezeit.log("更新到Xposed失败");
                return;
            default:
                freezeit.logFmt("更新到Xposed 未知回应[%d]", buff[0]);
                return;
            }
        }
        freezeit.logFmt("%s() 工作异常, 请确认LSPosed中冻它勾选系统框架, 然后重启 sendLen[%lu]", __FUNCTION__,
            tmp.length());
    }

    void loadLabelFile() {
        ifstream file(labelPath);

        if (!file.is_open()) {
            freezeit.logFmt("读取应用名称文件失败: [%s]", labelPath.c_str());
            return;
        }

        string line;
        while (getline(file, line)) {
            if (line.length() <= 2 || !isalpha(line[0])) {
                freezeit.logFmt("错误名称: [%s]", line.c_str());
                continue;
            }

            // package####label
            auto splitIdx = line.find("####");
            if (splitIdx == string::npos) {
                freezeit.logFmt("错误分割符: [%s]", line.c_str());
                continue;
            }
            auto it = uidIndex.find(line.substr(0, splitIdx));
            if (it != uidIndex.end() && contains(it->second))
                appInfoMap[it->second - UID_START].label = line.substr(splitIdx + 4);
        }
        file.close();
    }

    void loadLabel(const map<int, string>& labelList) {
        for (auto& [uid, label] : labelList)
            if (contains(uid))
                appInfoMap[uid - UID_START].label = label;
    }

    void saveLabel() {
        auto fd = open(labelPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd < 0) {
            freezeit.logFmt("保存应用名称文件失败: [%s]", labelPath.c_str());
            return;
        }

        string tmp;
        tmp.reserve(1024L * 16);
        for (const auto& appInfo : appInfoMap)
            if (appInfo.uid > 0 && appInfo.package != appInfo.label) {
                tmp += appInfo.package;
                tmp += "####";
                tmp += appInfo.label;
                tmp += '\n';
            }
        write(fd, tmp.c_str(), tmp.length());
        close(fd);
    }

};
