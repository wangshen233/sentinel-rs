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
