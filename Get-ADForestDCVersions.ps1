<#
.SYNOPSIS
    Показывает версию ОС и другую ключевую информацию о всех контроллерах
    домена (DC) во всём лесу Active Directory.

.DESCRIPTION
    1. Получает список доменов из текущего леса.
    2. Для каждого домена запрашивает все DC через Get-ADDomainController.
    3. Формирует объект с основными свойствами (Имя, Домен, Сайт, ОС, версия и т.д.).
    4. Сортирует и выводит таблицу; при желании можно экспортировать в CSV.

.NOTES
    Требуется: RSAT (модуль ActiveDirectory) или Windows Server с ролями AD DS.
    Запускать от учётки, у которой есть право читать каталог (обычно Authenticated Users).
#>

param(
    [switch]$ExportCsv,                 # При указании экспортирует в CSV
    [string]$Path = ".\DC_Versions.csv" # Путь к CSV-файлу
)

Import-Module ActiveDirectory -ErrorAction Stop

# Получаем объект леса
$forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

$dcInfo = foreach ($domain in $forest.Domains) {

    # Запрашиваем все контроллеры домена
    $dcs = Get-ADDomainController -Filter * -Server $domain.Name -ErrorAction SilentlyContinue

    foreach ($dc in $dcs) {
        # Формируем «плоский» объект
        [PSCustomObject]@{
            Forest               = $forest.Name
            Domain               = $domain.Name
            DC_Name              = $dc.HostName
            Site                 = $dc.Site
            IPv4Address          = $dc.IPv4Address
            OperatingSystem      = $dc.OperatingSystem
            OperatingSystemVers  = $dc.OperatingSystemVersion
            Hotfix               = $dc.Hotfix
            IsGlobalCatalog      = $dc.IsGlobalCatalog
            FSMO_Roles           = (
                @(
                    if ($dc.IsPdc)              {'PDC'}
                    if ($dc.IsRidMaster)        {'RID'}
                    if ($dc.IsInfrastructureMaster){'Infrastructure'}
                    if ($dc.IsSchemaMaster)     {'Schema'}
                    if ($dc.IsDomainNamingMaster){'DomainNaming'}
                ) -join ','
            )
        }
    }
}

# Если нужно сохранить в файл — делаем это до форматирования
if ($ExportCsv) {
    $dcInfo | Sort-Object Domain, DC_Name | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    Write-Host "Файл $Path сохранён." -ForegroundColor Green
}

# Красивый вывод в консоль
$dcInfo | Sort-Object Domain, DC_Name |
    Format-Table DC_Name,Domain,Site,OperatingSystem,OperatingSystemVers,IsGlobalCatalog,FSMO_Roles -AutoSize
