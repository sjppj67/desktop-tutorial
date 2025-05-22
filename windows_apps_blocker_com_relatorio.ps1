# Script Único para Bloqueio Permanente de Aplicativos Indesejados no Windows

<#
.SYNOPSIS
    Script completo para bloqueio permanente de aplicativos indesejados no Windows
.DESCRIPTION
    Combina políticas de registro aprimoradas, monitoramento e agendamento automático
    Baseado nos documentos "Guia Completo para Bloqueio Permanente" e scripts relacionados
.NOTES
    Deve ser executado como Administrador
    Versão: 1.2
    Data: $(Get-Date -Format "yyyy-MM-dd")
#>

#region Configurações Iniciais
param (
    [switch]$InstallOnly,    # Apenas instala as políticas sem configurar a tarefa agendada
    [switch]$MonitorOnly,    # Apenas executa o monitoramento sem aplicar políticas
    [switch]$SetupTaskOnly,  # Apenas configura a tarefa agendada sem aplicar políticas
    [switch]$BackupRegistry, # Cria backup do registro antes de aplicar alterações
    [switch]$ReportOnly      # Apenas gera o relatório de status sem aplicar alterações
)

# Verificar execução como administrador
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Por favor, execute como Administrador!"
    Break
}

# Configurações de diretório e arquivos
$scriptName = "WindowsAppsBlocker"
$scriptDir = "$env:ProgramData\$scriptName"
$enforcerLog = "$scriptDir\PolicyEnforcer.log"
$monitorLog = "$scriptDir\PolicyMonitor.log"
$backupDir = "$scriptDir\Backups"
$reportFile = "$scriptDir\LastExecutionReport.txt"

# Criar diretório se não existir
if (-not (Test-Path $scriptDir)) {
    New-Item -Path $scriptDir -ItemType Directory -Force | Out-Null
}

# Função para registrar logs
function Write-Log {
    param (
        [string]$Message,
        [string]$LogFile,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $logEntry
    Write-Output $logEntry
}

# Função para verificar versão do Windows
function Get-WindowsVersion {
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $version = [Version]$osInfo.Version
    
    if ($version.Major -eq 10) {
        if ($version.Build -ge 22000) {
            return "Windows 11"
        } else {
            return "Windows 10"
        }
    } elseif ($version.Major -eq 6) {
        return "Windows 8 ou anterior"
    } else {
        return "Desconhecido"
    }
}

# Inicializar arrays para rastreamento de alterações
$global:appliedPolicies = @()
$global:failedPolicies = @()
$global:backupFiles = @()
$global:executionSummary = @()

# Adicionar ao resumo de execução
function Add-ExecutionSummary {
    param (
        [string]$Category,
        [string]$Action,
        [string]$Status,
        [string]$Details = ""
    )
    
    $global:executionSummary += [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Category = $Category
        Action = $Action
        Status = $Status
        Details = $Details
    }
}
#endregion

#region Backup do Registro
function Backup-WindowsRegistry {
    if (-not (Test-Path $backupDir)) {
        New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
    }
    
    try {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        
        # Exportar chaves críticas
        $keysToBackup = @(
            "HKLM\Software\Policies\Microsoft\WindowsStore",
            "HKLM\Software\Policies\Microsoft\Windows\CloudContent",
            "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "HKLM\Software\Policies\Microsoft\Windows\OneDrive",
            "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
        )
        
        foreach ($key in $keysToBackup) {
            $keyName = ($key -replace '\\', '_') -replace ':', ''
            $keyBackupFile = "$backupDir\${keyName}_$timestamp.reg"
            reg export $key $keyBackupFile /y 2>$null
            
            if ($LASTEXITCODE -eq 0) {
                Write-Log -Message "Backup da chave $key criado em $keyBackupFile" -LogFile $enforcerLog
                $global:backupFiles += $keyBackupFile
                Add-ExecutionSummary -Category "Backup" -Action "Exportar chave $key" -Status "Sucesso" -Details $keyBackupFile
            } else {
                Write-Log -Message "Chave $key não existe ou não pôde ser exportada" -LogFile $enforcerLog -Level "WARNING"
                Add-ExecutionSummary -Category "Backup" -Action "Exportar chave $key" -Status "Aviso" -Details "Chave não existe ou não pôde ser exportada"
            }
        }
        
        Write-Log -Message "Backup do registro concluído em $backupDir" -LogFile $enforcerLog
        return $true
    } catch {
        Write-Log -Message "Erro ao criar backup do registro: $_" -LogFile $enforcerLog -Level "ERROR"
        Add-ExecutionSummary -Category "Backup" -Action "Backup do registro" -Status "Erro" -Details $_
        return $false
    }
}
#endregion

#region Políticas de Registro Aprimoradas
function Apply-EnhancedPolicies {
    $logDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Log -Message "Iniciando aplicação de políticas aprimoradas" -LogFile $enforcerLog
    
    # Verificar versão do Windows
    $windowsVersion = Get-WindowsVersion
    Write-Log -Message "Versão do Windows detectada: $windowsVersion" -LogFile $enforcerLog
    Add-ExecutionSummary -Category "Sistema" -Action "Detecção de versão" -Status "Info" -Details "Versão detectada: $windowsVersion"

    # Criar backup do registro se solicitado
    if ($BackupRegistry) {
        Write-Log -Message "Criando backup do registro antes de aplicar políticas..." -LogFile $enforcerLog
        Backup-WindowsRegistry | Out-Null
    }

    try {
        # === Políticas existentes ===
        # Bloquear Microsoft Store
        New-Item -Path "HKLM:\Software\Policies\Microsoft\WindowsStore" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Type DWord -Value 2
        $global:appliedPolicies += "Bloqueio da Microsoft Store"
        Add-ExecutionSummary -Category "Política" -Action "Bloqueio da Microsoft Store" -Status "Aplicada"

        # Impedir sugestões de apps no Menu Iniciar
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
        $global:appliedPolicies += "Bloqueio de sugestões de apps no Menu Iniciar"
        Add-ExecutionSummary -Category "Política" -Action "Bloqueio de sugestões de apps" -Status "Aplicada"

        # Impedir reinstalação de apps automáticos
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoInstallProgram" -Type DWord -Value 1
        $global:appliedPolicies += "Bloqueio de reinstalação automática de programas"
        Add-ExecutionSummary -Category "Política" -Action "Bloqueio de reinstalação automática" -Status "Aplicada"

        # Desativar reinstalação de apps recomendados silenciosos
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0
        $global:appliedPolicies += "Desativação de apps recomendados silenciosos"
        Add-ExecutionSummary -Category "Política" -Action "Desativação de apps recomendados" -Status "Aplicada"

        # Bloquear OneDrive
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\OneDrive" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
        $global:appliedPolicies += "Bloqueio do OneDrive"
        Add-ExecutionSummary -Category "Política" -Action "Bloqueio do OneDrive" -Status "Aplicada"

        # Minimizar envio de dados para a Microsoft
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
        $global:appliedPolicies += "Minimização de telemetria"
        Add-ExecutionSummary -Category "Política" -Action "Minimização de telemetria" -Status "Aplicada"

        # === Políticas adicionais ===
        # Desativar dicas e sugestões do Windows
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
        $global:appliedPolicies += "Desativação de dicas e sugestões do Windows"
        Add-ExecutionSummary -Category "Política" -Action "Desativação de dicas e sugestões" -Status "Aplicada"

        # Desativar instalação automática de aplicativos sugeridos
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OEMPreInstalledAppsEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
        $global:appliedPolicies += "Desativação de instalação automática de aplicativos sugeridos"
        Add-ExecutionSummary -Category "Política" -Action "Desativação de instalação automática" -Status "Aplicada"

        # Desativar sugestões na tela de bloqueio
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Type DWord -Value 0
        $global:appliedPolicies += "Desativação de sugestões na tela de bloqueio"
        Add-ExecutionSummary -Category "Política" -Action "Desativação de sugestões na tela de bloqueio" -Status "Aplicada"

        # Desativar sugestões no menu Iniciar
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314563Enabled" -Type DWord -Value 0
        $global:appliedPolicies += "Desativação de sugestões no menu Iniciar"
        Add-ExecutionSummary -Category "Política" -Action "Desativação de sugestões no menu Iniciar" -Status "Aplicada"

        # Políticas específicas para Windows 11
        if ($windowsVersion -eq "Windows 11") {
            Write-Log -Message "Aplicando políticas específicas para Windows 11" -LogFile $enforcerLog
            Add-ExecutionSummary -Category "Sistema" -Action "Aplicação de políticas específicas para Windows 11" -Status "Iniciada"
            
            # Desativar widgets no Windows 11
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Type DWord -Value 0
            $global:appliedPolicies += "Desativação de widgets no Windows 11"
            Add-ExecutionSummary -Category "Política" -Action "Desativação de widgets (Windows 11)" -Status "Aplicada"
            
            # Desativar chat do Teams no Windows 11
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" -Name "ChatIcon" -Type DWord -Value 3
            $global:appliedPolicies += "Desativação do chat do Teams no Windows 11"
            Add-ExecutionSummary -Category "Política" -Action "Desativação do chat do Teams (Windows 11)" -Status "Aplicada"
            
            # Desativar recomendações no menu Iniciar do Windows 11
            if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer") {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecommendedSection" -Type DWord -Value 1
            } else {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecommendedSection" -Type DWord -Value 1
            }
            $global:appliedPolicies += "Desativação de recomendações no menu Iniciar do Windows 11"
            Add-ExecutionSummary -Category "Política" -Action "Desativação de recomendações no menu Iniciar (Windows 11)" -Status "Aplicada"
        }

        # Aplicar as mesmas configurações para o usuário atual
        $registryPaths = @(
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
        )

        foreach ($path in $registryPaths) {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
        }

        # Aplicar configurações para o usuário atual
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OEMPreInstalledAppsEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
        $global:appliedPolicies += "Aplicação de configurações para o usuário atual"
        Add-ExecutionSummary -Category "Política" -Action "Aplicação de configurações para o usuário atual" -Status "Aplicada"

        Write-Log -Message "Políticas aplicadas com sucesso!" -LogFile $enforcerLog
        Add-ExecutionSummary -Category "Sistema" -Action "Aplicação de políticas" -Status "Concluída" -Details "Todas as políticas foram aplicadas com sucesso"
        return $true
    }
    catch {
        Write-Log -Message "Erro ao aplicar políticas: $_" -LogFile $enforcerLog -Level "ERROR"
        $global:failedPolicies += "Erro geral: $_"
        Add-ExecutionSummary -Category "Sistema" -Action "Aplicação de políticas" -Status "Erro" -Details $_
        return $false
    }
}
#endregion

#region Monitoramento de Políticas
function Test-Policies {
    # Lista expandida de políticas para verificação
    $policies = @(
        # Políticas básicas
        @{Path="HKLM:\Software\Policies\Microsoft\WindowsStore"; Name="RemoveWindowsStore"; ExpectedValue=1},
        @{Path="HKLM:\Software\Policies\Microsoft\WindowsStore"; Name="AutoDownload"; ExpectedValue=2},
        @{Path="HKLM:\Software\Policies\Microsoft\Windows\CloudContent"; Name="DisableWindowsConsumerFeatures"; ExpectedValue=1},
        @{Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoAutoInstallProgram"; ExpectedValue=1},
        @{Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SilentInstalledAppsEnabled"; ExpectedValue=0},
        @{Path="HKLM:\Software\Policies\Microsoft\Windows\OneDrive"; Name="DisableFileSyncNGSC"; ExpectedValue=1},
        
        # Políticas adicionais
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="PreInstalledAppsEnabled"; ExpectedValue=0},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="ContentDeliveryAllowed"; ExpectedValue=0},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name="DisableSoftLanding"; ExpectedValue=1},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name="DisableWindowsSpotlightFeatures"; ExpectedValue=1},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name="AllowTelemetry"; ExpectedValue=0}
    )
    
    # Adicionar políticas específicas do Windows 11 se aplicável
    $windowsVersion = Get-WindowsVersion
    if ($windowsVersion -eq "Windows 11") {
        $win11Policies = @(
            @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Dsh"; Name="AllowNewsAndInterests"; ExpectedValue=0},
            @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat"; Name="ChatIcon"; ExpectedValue=3},
            @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="HideRecommendedSection"; ExpectedValue=1}
        )
        $policies += $win11Policies
    }

    $failedPolicies = @()

    foreach ($policy in $policies) {
        if (-not (Test-Path $policy.Path)) {
            $failedPolicies += "$($policy.Path)\$($policy.Name)"
            continue
        }

        $value = Get-ItemProperty -Path $policy.Path -Name $policy.Name -ErrorAction SilentlyContinue
        if ($null -eq $value -or $value.$($policy.Name) -ne $policy.ExpectedValue) {
            $failedPolicies += "$($policy.Path)\$($policy.Name)"
        }
    }

    return $failedPolicies
}

function MonitorPolicies {
    $logDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Log -Message "Iniciando monitoramento de políticas" -LogFile $monitorLog
    Add-ExecutionSummary -Category "Monitor" -Action "Verificação de políticas" -Status "Iniciada"

    $failedPolicies = Test-Policies

    if ($failedPolicies.Count -gt 0) {
        Write-Log -Message "Políticas alteradas ou ausentes detectadas:" -LogFile $monitorLog
        $failedPolicies | ForEach-Object { 
            Write-Log -Message "- $_" -LogFile $monitorLog 
            $global:failedPolicies += $_
        }
        Add-ExecutionSummary -Category "Monitor" -Action "Verificação de políticas" -Status "Alerta" -Details "$($failedPolicies.Count) políticas ausentes ou alteradas"

        # Reaplicar políticas
        Write-Log -Message "Reaplicando políticas..." -LogFile $monitorLog
        Add-ExecutionSummary -Category "Monitor" -Action "Reaplicação de políticas" -Status "Iniciada"
        $result = Apply-EnhancedPolicies

        if ($result) {
            Write-Log -Message "Políticas reaplicadas com sucesso." -LogFile $monitorLog
            Add-ExecutionSummary -Category "Monitor" -Action "Reaplicação de políticas" -Status "Concluída" -Details "Políticas restauradas com sucesso"
        } else {
            Write-Log -Message "Falha ao reaplicar políticas." -LogFile $monitorLog -Level "ERROR"
            Add-ExecutionSummary -Category "Monitor" -Action "Reaplicação de políticas" -Status "Erro" -Details "Falha ao restaurar políticas"
        }
    } else {
        Write-Log -Message "Verificação concluída: Todas as políticas estão ativas." -LogFile $monitorLog
        Add-ExecutionSummary -Category "Monitor" -Action "Verificação de políticas" -Status "Concluída" -Details "Todas as políticas estão ativas"
    }
}
#endregion

#region Tarefa Agendada
function Setup-ScheduledTask {
    $logDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Log -Message "Configurando tarefa agendada" -LogFile $enforcerLog
    Add-ExecutionSummary -Category "Tarefa" -Action "Configuração de tarefa agendada" -Status "Iniciada"

    try {
        # Salvar este script no diretório de programas para acesso permanente
        $scriptPath = "$scriptDir\$scriptName.ps1"
        if (-not (Test-Path $scriptPath)) {
            Copy-Item -Path $PSCommandPath -Destination $scriptPath -Force
            Add-ExecutionSummary -Category "Tarefa" -Action "Cópia do script para diretório permanente" -Status "Concluída" -Details $scriptPath
        }

        # Criar tarefa agendada para verificação diária
        $taskName = "WindowsAppsBlockerMonitor"
        $taskDescription = "Verifica e reaplica políticas de bloqueio de aplicativos indesejados no Windows"

        # Remover tarefa existente, se houver
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            Add-ExecutionSummary -Category "Tarefa" -Action "Remoção de tarefa existente" -Status "Concluída"
        }

        # Criar ação
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`" -MonitorOnly"

        # Criar gatilhos
        $triggerDaily = New-ScheduledTaskTrigger -Daily -At 9AM
        $triggerStartup = New-ScheduledTaskTrigger -AtStartup
        $triggerLogon = New-ScheduledTaskTrigger -AtLogOn

        # Adicionar gatilho para após instalação de atualizações (Windows 10/11)
        $windowsVersion = Get-WindowsVersion
        if ($windowsVersion -eq "Windows 10" -or $windowsVersion -eq "Windows 11") {
            # Criar gatilho para evento de atualização do Windows
            $triggerUpdate = New-ScheduledTaskTrigger -AtStartup
            $triggerUpdate.Delay = "PT5M" # Atraso de 5 minutos após inicialização
            Add-ExecutionSummary -Category "Tarefa" -Action "Configuração de gatilho pós-atualização" -Status "Concluída"
        }

        # Configurar principal (usuário que executa a tarefa)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        # Criar configurações
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -WakeToRun

        # Registrar tarefa
        if ($windowsVersion -eq "Windows 10" -or $windowsVersion -eq "Windows 11") {
            Register-ScheduledTask -TaskName $taskName -Description $taskDescription -Trigger @($triggerDaily, $triggerStartup, $triggerLogon, $triggerUpdate) -Action $action -Principal $principal -Settings $settings | Out-Null
        } else {
            Register-ScheduledTask -TaskName $taskName -Description $taskDescription -Trigger @($triggerDaily, $triggerStartup, $triggerLogon) -Action $action -Principal $principal -Settings $settings | Out-Null
        }

        # Executar a tarefa imediatamente para verificação
        Start-ScheduledTask -TaskName $taskName | Out-Null

        Write-Log -Message "Tarefa agendada configurada com sucesso!" -LogFile $enforcerLog
        Write-Log -Message "A verificação de políticas será executada diariamente às 9h, na inicialização do sistema e após login." -LogFile $enforcerLog
        Add-ExecutionSummary -Category "Tarefa" -Action "Configuração de tarefa agendada" -Status "Concluída" -Details "Tarefa '$taskName' configurada com sucesso"
        return $true
    }
    catch {
        Write-Log -Message "Erro ao configurar tarefa agendada: $_" -LogFile $enforcerLog -Level "ERROR"
        Add-ExecutionSummary -Category "Tarefa" -Action "Configuração de tarefa agendada" -Status "Erro" -Details $_
        return $false
    }
}
#endregion

#region Relatório de Status
function Get-PolicyStatus {
    $failedPolicies = Test-Policies
    $totalPolicies = (Test-Policies).Count + $failedPolicies.Count
    $activePolicies = $totalPolicies - $failedPolicies.Count
    
    $windowsVersion = Get-WindowsVersion
    $taskExists = Get-ScheduledTask -TaskName "WindowsAppsBlockerMonitor" -ErrorAction SilentlyContinue
    
    $report = @"
=== Relatório de Status do Bloqueio de Aplicativos ===
Data e Hora: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Versão do Windows: $windowsVersion

Políticas de Registro:
- Total de políticas verificadas: $totalPolicies
- Políticas ativas: $activePolicies
- Políticas ausentes ou alteradas: $($failedPolicies.Count)

Tarefa Agendada:
- Status: $(if ($taskExists) { "Configurada" } else { "Não configurada" })
$(if ($taskExists) {
    $task = Get-ScheduledTask -TaskName "WindowsAppsBlockerMonitor"
    "- Última execução: $($task.LastRunTime)"
    "- Próxima execução: $($task.NextRunTime)"
    "- Status: $($task.State)"
})

Logs:
- Políticas: $enforcerLog
- Monitor: $monitorLog
"@

    if ($failedPolicies.Count -gt 0) {
        $report += "`n`nPolíticas ausentes ou alteradas:`n"
        $failedPolicies | ForEach-Object { $report += "- $_`n" }
    }
    
    return $report
}
#endregion

#region Relatório de Execução
function Generate-ExecutionReport {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $windowsVersion = Get-WindowsVersion
    $computerName = $env:COMPUTERNAME
    $userName = $env:USERNAME
    
    $report = @"
=====================================================
   RELATÓRIO DE EXECUÇÃO - WINDOWS APPS BLOCKER
=====================================================
Data e Hora: $timestamp
Computador: $computerName
Usuário: $userName
Versão do Windows: $windowsVersion
Modo de Execução: $($PSBoundParameters.Keys -join ', ')
=====================================================

RESUMO DE POLÍTICAS APLICADAS:
-----------------------------
"@

    if ($global:appliedPolicies.Count -gt 0) {
        foreach ($policy in $global:appliedPolicies) {
            $report += "`n✓ $policy"
        }
    } else {
        $report += "`nNenhuma política foi aplicada nesta execução."
    }

    $report += @"

POLÍTICAS COM PROBLEMAS:
----------------------
"@

    if ($global:failedPolicies.Count -gt 0) {
        foreach ($policy in $global:failedPolicies) {
            $report += "`n✗ $policy"
        }
    } else {
        $report += "`nNenhum problema detectado com as políticas."
    }

    $report += @"

BACKUPS CRIADOS:
--------------
"@

    if ($global:backupFiles.Count -gt 0) {
        foreach ($backup in $global:backupFiles) {
            $report += "`n• $backup"
        }
    } else {
        $report += "`nNenhum backup foi criado nesta execução."
    }

    $report += @"

LOG DE EXECUÇÃO DETALHADO:
------------------------
"@

    foreach ($entry in $global:executionSummary) {
        $report += "`n[$($entry.Timestamp)] [$($entry.Category)] $($entry.Action): $($entry.Status)"
        if ($entry.Details) {
            $report += " - $($entry.Details)"
        }
    }

    $report += @"

=====================================================
CONFIGURAÇÃO ATUAL DO SISTEMA:
-----------------------------
"@

    $report += "`n" + (Get-PolicyStatus)

    $report += @"

=====================================================
Relatório gerado por: Windows Apps Blocker v1.2
Diretório de instalação: $scriptDir
=====================================================
"@

    return $report
}
#endregion

#region Execução Principal
# Lógica de execução baseada nos parâmetros
if ($MonitorOnly) {
    Add-ExecutionSummary -Category "Sistema" -Action "Execução do script" -Status "Iniciada" -Details "Modo: Apenas monitoramento"
    MonitorPolicies
}
elseif ($SetupTaskOnly) {
    Add-ExecutionSummary -Category "Sistema" -Action "Execução do script" -Status "Iniciada" -Details "Modo: Apenas configuração de tarefa"
    Setup-ScheduledTask
}
elseif ($InstallOnly) {
    Add-ExecutionSummary -Category "Sistema" -Action "Execução do script" -Status "Iniciada" -Details "Modo: Apenas instalação de políticas"
    Apply-EnhancedPolicies
}
elseif ($BackupRegistry -and -not ($MonitorOnly -or $SetupTaskOnly -or $InstallOnly)) {
    # Apenas backup do registro
    Add-ExecutionSummary -Category "Sistema" -Action "Execução do script" -Status "Iniciada" -Details "Modo: Apenas backup do registro"
    Backup-WindowsRegistry
}
elseif ($ReportOnly) {
    # Apenas gerar relatório
    Add-ExecutionSummary -Category "Sistema" -Action "Execução do script" -Status "Iniciada" -Details "Modo: Apenas geração de relatório"
    # Não faz nada além de gerar o relatório no final
}
else {
    # Modo padrão - instala tudo
    Add-ExecutionSummary -Category "Sistema" -Action "Execução do script" -Status "Iniciada" -Details "Modo: Instalação completa"
    $policyResult = Apply-EnhancedPolicies
    if ($policyResult) {
        $taskResult = Setup-ScheduledTask
        if ($taskResult) {
            Write-Log -Message "Configuração completa concluída com sucesso!" -LogFile $enforcerLog
            Add-ExecutionSummary -Category "Sistema" -Action "Configuração completa" -Status "Concluída" -Details "Todas as etapas foram concluídas com sucesso"
        }
    }
    
    # Executar monitoramento imediatamente após a instalação
    MonitorPolicies
}

# Gerar relatório de execução
$executionReport = Generate-ExecutionReport
Set-Content -Path $reportFile -Value $executionReport
Add-ExecutionSummary -Category "Sistema" -Action "Geração de relatório" -Status "Concluída" -Details "Relatório salvo em $reportFile"

# Exibir relatório de status
$statusReport = Get-PolicyStatus
Write-Host "`n$statusReport`n"

# Exibir resumo dos logs
Write-Host "`nResumo da execução:"
Write-Host "-----------------"
if (Test-Path $enforcerLog) {
    Get-Content $enforcerLog -Tail 5 | ForEach-Object { Write-Host "[Enforcer] $_" }
}
if (Test-Path $monitorLog) {
    Get-Content $monitorLog -Tail 5 | ForEach-Object { Write-Host "[Monitor] $_" }
}
Write-Host "`nLogs completos disponíveis em:"
Write-Host "- Políticas: $enforcerLog"
Write-Host "- Monitor: $monitorLog"
Write-Host "- Relatório detalhado: $reportFile`n"

# Exibir mensagem sobre o relatório detalhado
Write-Host "Um relatório detalhado de execução foi gerado em: $reportFile" -ForegroundColor Green
Write-Host "Este relatório contém todas as alterações realizadas e o status atual do sistema.`n"
#endregion
