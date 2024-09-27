$ErrorActionPreference = 'Stop'

function log
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$LogMessage
    )
    Write-Output ("[{0}] {1}" -f (Get-Date), $LogMessage)
}

$clang = "D:/Android-NDK/toolchains/llvm/prebuilt/windows-x86_64/bin/clang++.exe"

$sysroot = "--sysroot=D:/Android-NDK/toolchains/llvm/prebuilt/windows-x86_64/sysroot"
$cppFlags = "--target=aarch64-linux-android31 -std=c++20 -static -s -Ofast -flto -funroll-loops -finline-functions -fomit-frame-pointer -Wall -Wextra -Wshadow -fno-exceptions -fno-rtti -DNDEBUG -fPIE"
log "正在创建临时文件夹"
rm ./build
mkdir ./build
log "构建中..."
& $clang $sysroot $cppFlags.Split(' ') -I. ./src/main.cpp -o build/Frozen

if (-not$?)
{
    log "构建失败"
    exit
}

log "Frozen编译成功"