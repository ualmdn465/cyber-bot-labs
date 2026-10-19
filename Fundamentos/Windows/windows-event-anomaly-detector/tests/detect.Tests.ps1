BeforeAll {
    $root = Resolve-Path "$PSScriptRoot/.."
    $shell = (Get-Process -Id $PID).Path   # pwsh o powershell.exe, el mismo que ejecuta Pester
    . "$root/detect.ps1"

    # Crea un evento con los campos que usa el detector.
    function New-TestEvent($Time, $Id, $User = "alice", $LogonType = "", $Group = "") {
        [pscustomobject]@{
            TimeCreated    = ([datetime]$Time).ToString("yyyy-MM-dd HH:mm:ss")
            EventId        = $Id
            TargetUserName = $User
            LogonType      = $LogonType
            IpAddress      = "198.51.100.10"
            GroupName      = $Group
        }
    }

    # N fallos 4625 de la misma cuenta separados por $StepSeconds.
    function New-Failures($Count, $StepSeconds) {
        1..$Count | ForEach-Object {
            New-TestEvent ([datetime]"2026-10-18T10:00:00").AddSeconds($_ * $StepSeconds) 4625 -LogonType 3
        }
    }
}

Describe "Regla BruteForce" {
    It "detecta 5 fallos en 5 minutos" {
        (Get-EventFindings -Events (New-Failures 5 30)).Rule | Should -Contain "BruteForce"
    }
    It "no dispara con 4 fallos (por debajo del umbral)" {
        (Get-EventFindings -Events (New-Failures 4 30)).Rule | Should -Not -Contain "BruteForce"
    }
    It "no dispara con 5 fallos repartidos en 20 minutos (fuera de la ventana)" {
        (Get-EventFindings -Events (New-Failures 5 300)).Rule | Should -Not -Contain "BruteForce"
    }
    It "emite un solo hallazgo por cuenta aunque haya muchos fallos" {
        @(Get-EventFindings -Events (New-Failures 20 10)).Count | Should -Be 1
    }
}

Describe "Regla RDPOutsideHours" {
    It "detecta logon tipo 10 a las 23:14" {
        $e = New-TestEvent "2026-10-18T23:14:00" 4624 -LogonType 10
        (Get-EventFindings -Events $e).Rule | Should -Contain "RDPOutsideHours"
    }
    It "ignora logon tipo 10 dentro del horario" {
        $e = New-TestEvent "2026-10-18T10:30:00" 4624 -LogonType 10
        Get-EventFindings -Events $e | Should -BeNullOrEmpty
    }
    It "ignora logon tipo 3 (red) fuera del horario" {
        $e = New-TestEvent "2026-10-18T23:14:00" 4624 -LogonType 3
        Get-EventFindings -Events $e | Should -BeNullOrEmpty
    }
}

Describe "Regla SensitiveGroupChange" {
    It "detecta alta en Administrators (4732, grupo local)" {
        $e = New-TestEvent "2026-10-18T23:20:00" 4732 -Group "Administrators"
        (Get-EventFindings -Events $e).Rule | Should -Contain "SensitiveGroupChange"
    }
    It "detecta alta en Domain Admins (4728, grupo global)" {
        $e = New-TestEvent "2026-10-18T23:20:00" 4728 -Group "Domain Admins"
        (Get-EventFindings -Events $e).Rule | Should -Contain "SensitiveGroupChange"
    }
    It "ignora un grupo no sensible" {
        $e = New-TestEvent "2026-10-18T23:20:00" 4732 -Group "Users"
        Get-EventFindings -Events $e | Should -BeNullOrEmpty
    }
}

Describe "Extremo a extremo con el generador" {
    BeforeAll {
        $csv = Join-Path $TestDrive "events.csv"
        $out = Join-Path $TestDrive "findings.csv"
        & "$root/generate-sample.ps1" -Out $csv | Out-Null
        $data = @(Import-Csv $csv)
    }
    It "genera 200 eventos" {
        $data.Count | Should -Be 200
    }
    It "solo usa IPs de documentación (RFC 5737)" {
        $data | Where-Object { $_.IpAddress -notmatch '^(192\.0\.2|198\.51\.100)\.\d+$' } | Should -BeNullOrEmpty
    }
    It "detecta exactamente los 3 patrones inyectados, sin extras" {
        $f = @(Get-EventFindings -Events $data)
        $f.Count | Should -Be 3
        ($f.Rule | Sort-Object) -join "," | Should -Be "BruteForce,RDPOutsideHours,SensitiveGroupChange"
        ($f.Target | Sort-Object) -join "," | Should -Be "test_admin_change,test_bruteforce,test_rdp"
    }
    It "sale con código 1 cuando hay hallazgos y escribe el CSV" {
        & $shell -NoProfile -File "$root/detect.ps1" -In $csv -Out $out | Out-Null
        $LASTEXITCODE | Should -Be 1
        @(Import-Csv $out).Count | Should -Be 3
    }
    It "sale con código 2 si el fichero de entrada no existe" {
        & $shell -NoProfile -File "$root/detect.ps1" -In (Join-Path $TestDrive "no-existe.csv") 2>$null | Out-Null
        $LASTEXITCODE | Should -Be 2
    }
}
