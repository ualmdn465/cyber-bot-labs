[CmdletBinding()]
param(
    [Alias('In')]
    [string]$InputPath = (Join-Path $PSScriptRoot "data/synthetic-events.csv"),
    [Alias('Out')]
    [string]$OutputPath = (Join-Path $PSScriptRoot "findings.csv"),
    [int]$FailureThreshold = 5,
    [int]$WindowMinutes = 5
)

$ErrorActionPreference = "Stop"

function Get-EventFindings {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Events,
        [int]$FailureThreshold = 5,
        [int]$WindowMinutes = 5
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $culture = [System.Globalization.CultureInfo]::InvariantCulture

    # $event es una variable automática de PowerShell: no se reutiliza como nombre de bucle.
    $parsed = foreach ($e in $Events) {
        $date = [datetime]::MinValue
        # Formato fijo e independiente de la configuración regional del equipo.
        if ([datetime]::TryParseExact([string]$e.TimeCreated, "yyyy-MM-dd HH:mm:ss", $culture,
                [System.Globalization.DateTimeStyles]::None, [ref]$date)) {
            [pscustomobject]@{
                Time      = $date
                EventId   = [int]$e.EventId
                User      = [string]$e.TargetUserName
                LogonType = [string]$e.LogonType
                GroupName = [string]$e.GroupName
                IpAddress = [string]$e.IpAddress
            }
        } else {
            Write-Warning "Fecha no válida, evento ignorado: '$($e.TimeCreated)'"
        }
    }

    # Regla 1 (T1110): >= FailureThreshold fallos 4625 de una cuenta en WindowMinutes.
    $failures = @($parsed | Where-Object { $_.EventId -eq 4625 })
    foreach ($userGroup in ($failures | Group-Object User)) {
        $userEvents = @($userGroup.Group | Sort-Object Time)
        for ($i = 0; $i -lt $userEvents.Count; $i++) {
            $windowEnd = $userEvents[$i].Time.AddMinutes($WindowMinutes)
            $windowEvents = @($userEvents | Where-Object {
                $_.Time -ge $userEvents[$i].Time -and $_.Time -le $windowEnd
            })
            if ($windowEvents.Count -ge $FailureThreshold) {
                $findings.Add([pscustomobject]@{
                    Rule        = "BruteForce"
                    Severity    = "High"
                    TimeCreated = $userEvents[$i].Time.ToString("yyyy-MM-dd HH:mm:ss")
                    Target      = $userGroup.Name
                    Details     = "$($windowEvents.Count) fallos en una ventana de $WindowMinutes minutos"
                    SourceIp    = $windowEvents[-1].IpAddress
                })
                break   # un hallazgo por cuenta
            }
        }
    }

    # Regla 2 (T1078 + T1021.001): logon correcto tipo 10 (RemoteInteractive) fuera de 08:00-18:00.
    $rdp = $parsed | Where-Object { $_.EventId -eq 4624 -and $_.LogonType -eq "10" }
    foreach ($e in $rdp) {
        if ($e.Time.TimeOfDay -lt [timespan]"08:00:00" -or $e.Time.TimeOfDay -ge [timespan]"18:00:00") {
            $findings.Add([pscustomobject]@{
                Rule        = "RDPOutsideHours"
                Severity    = "Medium"
                TimeCreated = $e.Time.ToString("yyyy-MM-dd HH:mm:ss")
                Target      = $e.User
                Details     = "Inicio de sesión RDP fuera de 08:00-18:00"
                SourceIp    = $e.IpAddress
            })
        }
    }

    # Regla 3 (T1098.007): alta en grupo privilegiado.
    # El ID depende del ámbito del grupo: 4728 global (Domain Admins),
    # 4732 local / dominio local (Administrators), 4756 universal (Enterprise/Schema Admins).
    $groupAddIds = 4728, 4732, 4756
    $sensitiveGroups = "Administrators", "Administradores", "Domain Admins",
                       "Admins. del dominio", "Enterprise Admins", "Schema Admins"
    $changes = $parsed | Where-Object { $_.EventId -in $groupAddIds -and $_.GroupName -in $sensitiveGroups }
    foreach ($e in $changes) {
        $findings.Add([pscustomobject]@{
            Rule        = "SensitiveGroupChange"
            Severity    = "High"
            TimeCreated = $e.Time.ToString("yyyy-MM-dd HH:mm:ss")
            Target      = $e.User
            Details     = "Evento $($e.EventId): alta en el grupo $($e.GroupName)"
            SourceIp    = $e.IpAddress
        })
    }

    return @($findings)
}

# Si el script se carga con dot-sourcing (tests), solo se define la función.
if ($MyInvocation.InvocationName -eq '.') { return }

# -ErrorAction Continue: con $ErrorActionPreference = "Stop", Write-Error lanzaría una
# excepción y el script acabaría con código 1 (igual que "hay hallazgos") en vez de 2.
if (-not (Test-Path -LiteralPath $InputPath -PathType Leaf)) {
    Write-Error "No existe el fichero de entrada: $InputPath" -ErrorAction Continue
    exit 2
}
if ($FailureThreshold -lt 1 -or $WindowMinutes -lt 1) {
    Write-Error "FailureThreshold y WindowMinutes deben ser mayores que cero." -ErrorAction Continue
    exit 2
}

try {
    $events = @(Import-Csv -LiteralPath $InputPath)
    $findings = @(Get-EventFindings -Events $events -FailureThreshold $FailureThreshold -WindowMinutes $WindowMinutes)
    $outDir = Split-Path -Parent $OutputPath
    if ($outDir) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    if ($findings.Count -gt 0) {
        $findings | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath $OutputPath
        Write-Host "Detectados $($findings.Count) hallazgos. Resultado: $OutputPath"
        exit 1
    }
    "Rule,Severity,TimeCreated,Target,Details,SourceIp" | Set-Content -Encoding UTF8 -LiteralPath $OutputPath
    Write-Host "Sin hallazgos. Resultado: $OutputPath"
    exit 0
} catch {
    Write-Error "Error procesando eventos: $_" -ErrorAction Continue
    exit 2
}
