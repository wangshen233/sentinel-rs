#Requires -Version 5.1
<#
.SYNOPSIS
    sentinel-rs 的**唯一受支持**构建入口（BoringSSL 需要 MSVC 环境）。

.DESCRIPTION
    wreq 的 TLS 后端是 BoringSSL（btls / btls-sys），构建时要现场编译：
      * C/C++ 编译器 + Windows SDK  → 来自 VS2022 的 vcvars64.bat
      * nasm                        → BoringSSL 的汇编模块
      * Strawberry Perl             → BoringSSL 的生成脚本
      * libclang (LLVM)             → btls-sys 的 bindgen，需 LIBCLANG_PATH

    直接在普通 PowerShell 里 `cargo build` 会挂在 btls-sys 的 bindgen 或
    nmake/cl.exe 找不到。所以：**先跑这个脚本**，它会 call vcvars64、导入
    环境变量、设置 LIBCLANG_PATH / PATH，再执行 cargo。

.PARAMETER Test
    改为执行 `cargo test --release`（其余参数照样透传）。

.PARAMETER CargoArgs
    透传给 cargo 的额外参数，例如 `.\build.ps1 --features foo`。

.EXAMPLE
    .\build.ps1

.EXAMPLE
    .\build.ps1 --bin tls_probe

.EXAMPLE
    .\build.ps1 -Test
#>
[CmdletBinding()]
param(
    [switch] $Test,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $CargoArgs
)

$ErrorActionPreference = 'Stop'

$Root      = Split-Path -Parent $MyInvocation.MyCommand.Path
$VcVars    = 'C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat'
$LlvmDir   = 'C:\Program Files\LLVM\bin'
$LibClang  = Join-Path $LlvmDir 'libclang.dll'

# ── 0) 非 ASCII 路径兜底（BoringSSL 的 nasm 打不开中文目录）──────────────
# btls-sys 用 nasm 汇编 BoringSSL 的 .asm；nasm 按 ANSI 打开路径，项目目录里
# 只要有中文（例如桌面的「新建文件夹 (4)」），cmake 的 asm 步骤就会
#   MSB3721: nasm ... 已退出，返回代码为 1（Unable to open input file）
# 整个构建直接失败。这里自动建一个**固定名字**的 ASCII 目录联接（junction）
# 指向当前项目的父目录，再从联接路径进去跑 cargo —— 产物落在同一个物理
# target\release\ 里（不是另一个目录），只是路径写法变成 ASCII。
#
# 联接名固定为 C:\sentinel-rs-ascii（可用 SENTINEL_ASCII_ROOT 覆盖），并且
# 每次都校验它指向**当前**项目的父目录：指向旧路径就拆掉重建，避免复用了一个
# 指向别处的联接这种隐蔽错配置。
$AsciiLinkName = if ($env:SENTINEL_ASCII_ROOT) { $env:SENTINEL_ASCII_ROOT } else { 'C:\sentinel-rs-ascii' }
if ($Root -notmatch '[^\x00-\x7F]') {
    Write-Host "[build] 项目路径已是纯 ASCII，无需联接兜底（忽略 $AsciiLinkName）"
} else {
    $ParentDir = Split-Path -Parent $Root
    $needCreate = $true
    if (Test-Path -LiteralPath $AsciiLinkName) {
        $existing = Get-Item -LiteralPath $AsciiLinkName -Force
        if ($existing.LinkType -ne 'Junction') {
            throw "$AsciiLinkName 已存在且不是目录联接；请删掉它，或用 SENTINEL_ASCII_ROOT 指定另一个位置"
        }
        $target = $existing.Target
        if ($target -and ($target -eq $ParentDir)) {
            $needCreate = $false
            Write-Host "[build] ASCII 联接复用：$AsciiLinkName -> $ParentDir"
        } else {
            Write-Host "[build] ASCII 联接指向旧路径（$target），重建为 $ParentDir"
            # 只删联接本身（rmdir 不会动目标目录的内容）
            cmd.exe /c rmdir "$AsciiLinkName" | Out-Null
        }
    }
    if ($needCreate) {
        cmd.exe /c mklink /J "$AsciiLinkName" "$ParentDir" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "创建 ASCII 目录联接失败：mklink /J `"$AsciiLinkName`" `"$ParentDir`""
        }
        Write-Host "[build] 非 ASCII 路径兜底：$AsciiLinkName -> $ParentDir"
    }
    $Root = Join-Path $AsciiLinkName (Split-Path -Leaf $Root)
    if (-not (Test-Path -LiteralPath (Join-Path $Root 'Cargo.toml'))) {
        throw "ASCII 联接不可用：$Root\Cargo.toml 不存在（检查 $AsciiLinkName 是否指向 $ParentDir）"
    }
    Write-Host "[build] 从 ASCII 路径构建：$Root（nasm 需要；产物仍在本项目 target\release\）"
}

if (-not (Test-Path -LiteralPath $VcVars)) {
    throw "找不到 vcvars64.bat：$VcVars（需要安装 VS2022 的 C++ 桌面开发工作负载）"
}
if (-not (Test-Path -LiteralPath $LibClang)) {
    throw "找不到 $LibClang（btls-sys 的 bindgen 需要 libclang；装 LLVM 或改本脚本的 `$LlvmDir）"
}

# ── 1) 把 vcvars64 的环境变量搬进当前 PowerShell 进程 ─────────────────────
# 直接 `& $VcVars` 只会污染一个子进程，父进程拿不到。用 cmd 跑一次再回收 `set` 输出。
Write-Host "[build] vcvars64 : $VcVars"
$vcEnv = & cmd.exe /c "call `"$VcVars`" >nul 2>&1 && set"
if ($LASTEXITCODE -ne 0) {
    throw "call vcvars64.bat 失败（exit $LASTEXITCODE）"
}
$imported = 0
foreach ($line in $vcEnv) {
    if ($line -match '^([^=]+)=(.*)$') {
        [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2])
        $imported++
    }
}
Write-Host "[build] 导入环境变量 : $imported 项"

# ── 2) libclang（btls-sys bindgen）────────────────────────────────────────
$env:LIBCLANG_PATH = $LlvmDir
if ($env:PATH -notlike "*$LlvmDir*") {
    $env:PATH = "$LlvmDir;$env:PATH"
}
Write-Host "[build] LIBCLANG_PATH: $env:LIBCLANG_PATH"

# ── 3) cargo ──────────────────────────────────────────────────────────────
$extra = @($CargoArgs | Where-Object { $_ -ne '' })
$cargo = if ($Test) { @('test', '--release') } else { @('build', '--release') }
$cargo = @($cargo + $extra)

Push-Location -LiteralPath $Root
try {
    Write-Host "[build] cargo $($cargo -join ' ')"
    & cargo @cargo
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $code
