$InputFile  = Join-Path -Path (Get-Location) -ChildPath 'flag.txt.lock'
$OutputFile = 'flag_decrypted.txt'

if (-not (Test-Path -LiteralPath $InputFile -PathType Leaf)) {
  throw "找不到加密檔案: $InputFile"
}

$in = [IO.File]::OpenRead($InputFile)

try {
  # 讀取前 8 bytes (Unix 時間戳)
  $unixBytes = New-Object byte[] 8
  $in.Read($unixBytes, 0, 8) | Out-Null
  $UnixTime = [BitConverter]::ToInt64($unixBytes, 0)
  
  Write-Host "Unix 時間戳: $UnixTime"
  
  # 從時間戳生成金鑰
  $md5 = [System.Security.Cryptography.MD5]::Create()
  try {
    $keyMaterial = [Text.Encoding]::UTF8.GetBytes([string]$UnixTime)
    $Key = $md5.ComputeHash($keyMaterial)
    Write-Host "金鑰 (hex): $([BitConverter]::ToString($Key).Replace('-',''))"
  } finally {
    $md5.Dispose()
  }
  
  # 讀取接下來 16 bytes (IV)
  $IV = New-Object byte[] 16
  $in.Read($IV, 0, 16) | Out-Null
  Write-Host "IV (hex): $([BitConverter]::ToString($IV).Replace('-',''))"
  
  # 設定 AES 解密器
  $AES = [System.Security.Cryptography.Aes]::Create()
  $AES.Mode    = [System.Security.Cryptography.CipherMode]::CBC
  $AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
  $AES.Key     = $Key
  $AES.IV      = $IV
  
  # 解密
  $out = [IO.File]::Create($OutputFile)
  try {
    $dec = $AES.CreateDecryptor()
    $crypto = New-Object System.Security.Cryptography.CryptoStream(
      $in, $dec, [System.Security.Cryptography.CryptoStreamMode]::Read
    )
    try {
      $crypto.CopyTo($out)
      Write-Host "`n解密成功! 輸出檔案: $OutputFile" -ForegroundColor Green
    } finally {
      $crypto.Dispose()
    }
  } finally {
    $out.Dispose()
    $AES.Dispose()
  }
  
} finally {
  $in.Dispose()
}

# 顯示解密內容
if (Test-Path $OutputFile) {
  $bytes = [IO.File]::ReadAllBytes($OutputFile)
  $utf8  = [Text.Encoding]::UTF8.GetString($bytes)
  $ascii = [Text.Encoding]::ASCII.GetString($bytes)

  Write-Host "`n解密內容 (UTF-8):" -ForegroundColor Cyan
  Write-Host $utf8
  Write-Host "`n解密內容 (ASCII):" -ForegroundColor Cyan
  Write-Host $ascii
  Write-Host "`n解密內容 (Hex):" -ForegroundColor Cyan
  Write-Host ([BitConverter]::ToString($bytes).Replace('-',' '))
}
