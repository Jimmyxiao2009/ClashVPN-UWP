# ClashVPN 一键出包：MSBuild 编译(ARM) -> 10240 makeappx 打包 -> signtool 签名
# 用法: pwsh -File pack.ps1   [-Config Debug|Release]
# 说明: VS/新版 makeappx 会因 windows.vpnPlugin schema 报 C00CE169；源清单里该扩展保持注释，
#       这里只让 MSBuild 编译出布局，再用 10240 代的 makeappx(bin\x86, /l) 打包。
#       包内仍含 ClashVPN.Plugin.winmd + networkingVpnProvider，IVpnPlugIn 可被系统激活。
param([string]$Config = "Debug")

$root   = Split-Path -Parent $MyInvocation.MyCommand.Path
$msb    = "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\MSBuild\15.0\Bin\MSBuild.exe"
$mk     = "C:\Program Files (x86)\Windows Kits\10\bin\x86\makeappx.exe"            # 10240
$st     = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.15063.0\x86\signtool.exe"
$pfx    = "$root\ClashVPN\ClashVPN_TemporaryKey.pfx"                                # 密码 clashvpn
$layout = "$root\ClashVPN\bin\ARM\$Config"
$outDir = "$root\ClashVPN\AppPackages\ClashVPN_$Config"
$appx   = "$outDir\ClashVPN_1.0.0.0_ARM_$Config.appx"

Write-Host "==> 1/3 还原 + 编译 (ARM $Config)..." -ForegroundColor Cyan
& $msb "$root\ClashVPN.sln" /t:Restore  /p:Configuration=$Config /p:Platform=ARM /p:VisualStudioVersion=15.0 /nologo /v:m | Out-Null
# 整个 Build 会在自带打包步骤可能失败，但布局已生成 —— 忽略其退出码。
& $msb "$root\ClashVPN.sln" /p:Configuration=$Config /p:Platform=ARM /p:VisualStudioVersion=15.0 /p:AppxPackageSigningEnabled=false /nologo /v:m 2>&1 | Out-Null

if (-not (Test-Path "$layout\AppxManifest.xml") -or -not (Test-Path "$layout\ClashVPN.exe")) {
    Write-Host "编译未产出布局（真正的编译错误，看上面输出）。" -ForegroundColor Red; exit 1
}

Write-Host "==> 2/3 10240 makeappx 打包..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force $outDir | Out-Null
& $mk pack /d $layout /p $appx /o /l
if ($LASTEXITCODE -ne 0) { Write-Host "makeappx 失败" -ForegroundColor Red; exit 1 }

Write-Host "==> 3/3 签名..." -ForegroundColor Cyan
& $st sign /fd SHA256 /f $pfx /p "clashvpn" $appx
if ($LASTEXITCODE -ne 0) { Write-Host "签名失败" -ForegroundColor Red; exit 1 }

Copy-Item "$root\ClashVPN\ClashVPN_TemporaryKey.cer" $outDir -Force
Write-Host "`n完成: $appx ($([math]::Round((Get-Item $appx).Length/1MB,2)) MB)" -ForegroundColor Green
Write-Host "  证书: $outDir\ClashVPN_TemporaryKey.cer" -ForegroundColor Green
