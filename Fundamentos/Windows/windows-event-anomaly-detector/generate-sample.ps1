[CmdletBinding()]
param(
    [Alias('Out')]
    [string]$OutputPath = (Join-Path $PSScriptRoot "data/synthetic-events.csv")
)

$ErrorActionPreference = "Stop"
$directory = Split-Path -Parent $OutputPath
if ($directory) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }

# Esquema plano y simplificado. En el evento real 4732, TargetUserName es el GRUPO
# y el miembro añadido va en MemberName/MemberSid; aquí TargetUserName = cuenta afectada
# y GroupName = grupo, para que todas las reglas usen las mismas columnas.
# IPs: solo rangos de documentación RFC 5737 (192.0.2.0/24 y 198.51.100.0/24).
function New-Event($Time, $Id, $User, $LogonType, $Ip, $Group = "") {
    [pscustomobject]@{
        TimeCreated    = ([datetime]$Time).ToString("yyyy-MM-dd HH:mm:ss")
        EventId        = $Id
        TargetUserName = $User
        LogonType      = $LogonType
        IpAddress      = $Ip
        GroupName      = $Group
        Computer       = "LAB-WIN01"
    }
}

$events = [System.Collections.Generic.List[object]]::new()

# --- Ruido benigno: debe NO generar hallazgos con el umbral elegido (5 fallos / 5 min) ---
# Usuario que se equivoca 3 veces escribiendo la contraseña.
foreach ($s in 0, 20, 40) { $events.Add((New-Event ([datetime]"2026-10-18T09:30:00").AddSeconds($s) 4625 "user3" 2 "192.0.2.13")) }
# Cuenta de servicio con credencial caducada: falla cada 15 min (patrón regular, lento).
for ($i = 0; $i -lt 4; $i++) { $events.Add((New-Event ([datetime]"2026-10-18T10:00:00").AddMinutes($i * 15) 4625 "svc_backup" 3 "192.0.2.50")) }
# RDP legítimo dentro del horario.
$events.Add((New-Event "2026-10-18T10:30:00" 4624 "user5" 10 "192.0.2.25"))
# Alta en un grupo no sensible.
$events.Add((New-Event "2026-10-18T11:00:00" 4732 "user7" "" "192.0.2.27" "Users"))

# --- Patrones maliciosos inyectados (exactamente 3 hallazgos esperados) ---
# 1) Fuerza bruta: 5 fallos sobre la misma cuenta en 2 minutos.
for ($i = 0; $i -lt 5; $i++) { $events.Add((New-Event ([datetime]"2026-10-18T22:00:00").AddSeconds($i * 30) 4625 "test_bruteforce" 3 "198.51.100.77")) }
# 2) RDP correcto fuera de horario.
$events.Add((New-Event "2026-10-18T23:14:00" 4624 "test_rdp" 10 "198.51.100.88"))
# 3) Alta en el grupo local Administrators.
$events.Add((New-Event "2026-10-18T23:20:00" 4732 "test_admin_change" "" "198.51.100.99" "Administrators"))

# --- Actividad normal de relleno hasta 200 eventos (logon interactivo en horario) ---
$base = [datetime]"2026-10-18T09:00:00"
$fill = 200 - $events.Count
for ($i = 0; $i -lt $fill; $i++) {
    $events.Add((New-Event $base.AddMinutes($i) 4624 "user$($i % 12)" 2 "192.0.2.$(($i % 200) + 1)"))
}

$events | Sort-Object TimeCreated | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputPath
Write-Host "Generados $($events.Count) eventos sintéticos en $OutputPath"
