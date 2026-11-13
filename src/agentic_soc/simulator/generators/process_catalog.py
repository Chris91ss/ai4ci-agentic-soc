"""Endpoint process catalog: parent->child launch tables and command-line templates."""

from __future__ import annotations

# (parent, child, weight)
Launch = tuple[str, str, float]

WORKSTATION_COMMON: list[Launch] = [
    ("explorer.exe", "chrome.exe", 8.0),
    ("chrome.exe", "chrome.exe", 18.0),
    ("explorer.exe", "msedge.exe", 3.0),
    ("msedge.exe", "msedge.exe", 7.0),
    ("explorer.exe", "outlook.exe", 1.2),
    ("outlook.exe", "winword.exe", 0.8),
    ("outlook.exe", "excel.exe", 0.8),
    ("outlook.exe", "acrord32.exe", 0.4),
    ("explorer.exe", "teams.exe", 0.8),
    ("teams.exe", "msedgewebview2.exe", 3.0),
    ("explorer.exe", "excel.exe", 1.5),
    ("explorer.exe", "winword.exe", 1.2),
    ("explorer.exe", "notepad.exe", 0.4),
    ("svchost.exe", "taskhostw.exe", 2.5),
    ("svchost.exe", "backgroundTaskHost.exe", 2.0),
    ("svchost.exe", "RuntimeBroker.exe", 2.0),
    ("services.exe", "svchost.exe", 0.8),
    ("svchost.exe", "MpCmdRun.exe", 0.25),
    ("svchost.exe", "wuauclt.exe", 0.25),
    ("explorer.exe", "OneDrive.exe", 0.2),
    ("svchost.exe", "SearchProtocolHost.exe", 1.2),
    ("explorer.exe", "SnippingTool.exe", 0.2),
]

ROLE_EXTRA: dict[str, list[Launch]] = {
    "engineering": [
        ("explorer.exe", "code.exe", 1.5),
        ("code.exe", "git.exe", 3.0),
        ("code.exe", "node.exe", 2.0),
        ("code.exe", "python.exe", 1.5),
        ("explorer.exe", "WindowsTerminal.exe", 1.0),
        ("WindowsTerminal.exe", "powershell.exe", 1.5),
        ("powershell.exe", "git.exe", 1.2),
        ("powershell.exe", "python.exe", 1.0),
        ("node.exe", "node.exe", 1.5),
        ("python.exe", "python.exe", 0.6),
        ("explorer.exe", "cmd.exe", 0.4),
        ("cmd.exe", "git.exe", 0.5),
        ("code.exe", "cmd.exe", 0.5),
        ("git.exe", "git-remote-https.exe", 1.5),
    ],
    "it_admin": [
        ("explorer.exe", "mmc.exe", 1.5),
        ("explorer.exe", "mstsc.exe", 1.5),
        ("explorer.exe", "powershell.exe", 2.0),
        ("powershell.exe", "net.exe", 0.35),
        ("powershell.exe", "nltest.exe", 0.1),
        ("explorer.exe", "cmd.exe", 1.0),
        ("cmd.exe", "ipconfig.exe", 0.5),
        ("cmd.exe", "ping.exe", 0.6),
        ("explorer.exe", "putty.exe", 0.8),
        ("explorer.exe", "WindowsTerminal.exe", 0.8),
        ("WindowsTerminal.exe", "powershell.exe", 1.0),
    ],
    "finance": [
        ("explorer.exe", "saplogon.exe", 2.0),
        ("saplogon.exe", "excel.exe", 0.8),
        ("explorer.exe", "acrord32.exe", 0.8),
    ],
    "operations": [("explorer.exe", "saplogon.exe", 2.0), ("saplogon.exe", "excel.exe", 0.5)],
    "sales": [
        ("explorer.exe", "zoom.exe", 0.8),
        ("explorer.exe", "powerpnt.exe", 0.8),
        ("outlook.exe", "powerpnt.exe", 0.3),
    ],
    "executive": [("explorer.exe", "powerpnt.exe", 1.0), ("explorer.exe", "zoom.exe", 0.8)],
    "marketing": [("explorer.exe", "photoshop.exe", 0.8), ("explorer.exe", "slack.exe", 0.8)],
    "support": [("explorer.exe", "slack.exe", 1.0)],
    "hr": [("explorer.exe", "acrord32.exe", 0.8)],
}

LOGON_TREE: list[tuple[str, str]] = [
    ("winlogon.exe", "userinit.exe"),
    ("userinit.exe", "explorer.exe"),
    ("svchost.exe", "sihost.exe"),
    ("svchost.exe", "ctfmon.exe"),
    ("explorer.exe", "OneDrive.exe"),
    ("explorer.exe", "teams.exe"),
    ("explorer.exe", "outlook.exe"),
]

RDP_SESSION_TREE: list[tuple[str, str]] = [
    ("svchost.exe", "rdpclip.exe"),
    ("winlogon.exe", "userinit.exe"),
    ("userinit.exe", "explorer.exe"),
]
RDP_SESSION_TOOLS: list[Launch] = [
    ("explorer.exe", "mmc.exe", 2.0),
    ("explorer.exe", "powershell.exe", 1.5),
    ("explorer.exe", "taskmgr.exe", 1.0),
    ("explorer.exe", "ServerManager.exe", 1.0),
    ("powershell.exe", "Get-WindowsUpdate.exe", 0.2),
]

WINDOWS_SERVER_COMMON: list[Launch] = [
    ("services.exe", "svchost.exe", 2.0),
    ("svchost.exe", "taskhostw.exe", 2.0),
    ("svchost.exe", "WmiPrvSE.exe", 1.5),
    ("svchost.exe", "MpCmdRun.exe", 0.3),
    ("svchost.exe", "TiWorker.exe", 0.3),
    ("services.exe", "msiexec.exe", 0.1),
    ("svchost.exe", "conhost.exe", 0.5),
]
LINUX_SERVER_COMMON: list[Launch] = [
    ("systemd", "sshd", 0.4),
    ("sshd", "bash", 0.4),
    ("cron", "bash", 1.0),
    ("bash", "python3", 0.5),
    ("bash", "curl", 0.4),
    ("systemd", "systemd-journald", 0.2),
    ("bash", "logrotate", 0.2),
]
SERVER_ROLE: dict[str, list[Launch]] = {
    "dc": [("services.exe", "dfsrs.exe", 0.5), ("svchost.exe", "dns.exe", 0.3)],
    "file": [("svchost.exe", "srmhost.exe", 0.4)],
    "db": [
        ("services.exe", "sqlservr.exe", 0.2),
        ("sqlservr.exe", "sqlceip.exe", 0.3),
        ("sqlagent.exe", "cmd.exe", 0.2),
        ("cmd.exe", "bcp.exe", 0.2),
    ],
    "erp": [("services.exe", "disp+work.exe", 0.3)],
    "mail": [("services.exe", "MSExchangeTransport.exe", 0.3), ("w3wp.exe", "csc.exe", 0.15)],
    "backup": [("services.exe", "BackupAgent.exe", 0.3)],
    "jump": [("svchost.exe", "rdpclip.exe", 0.5), ("explorer.exe", "mstsc.exe", 0.8)],
    "edr": [("services.exe", "EdrManager.exe", 0.2)],
    "wsus": [("services.exe", "WsusService.exe", 0.2), ("w3wp.exe", "w3wp.exe", 0.3)],
    "print": [("services.exe", "spoolsv.exe", 0.1), ("spoolsv.exe", "PrintIsolationHost.exe", 0.5)],
    "app": [("systemd", "java", 0.2), ("java", "java", 0.5)],
    "web": [("systemd", "nginx", 0.2), ("nginx", "nginx", 0.8)],
    "proxy": [("systemd", "squid", 0.2), ("squid", "squid", 0.6)],
    "vpn": [("systemd", "openvpn", 0.2), ("openvpn", "openvpn", 0.3)],
    "monitoring": [
        ("systemd", "prometheus", 0.1),
        ("cron", "bash", 0.8),
        ("bash", "check_http", 0.8),
    ],
    "build": [
        ("systemd", "gitlab-runner", 0.2),
        ("gitlab-runner", "bash", 1.5),
        ("bash", "docker", 1.0),
        ("bash", "make", 0.8),
        ("make", "gcc", 1.0),
        ("bash", "git", 1.0),
    ],
}
BACKUP_JOB: list[tuple[str, str]] = [
    ("services.exe", "BackupAgent.exe"),
    ("BackupAgent.exe", "vssadmin.exe"),
    ("BackupAgent.exe", "robocopy.exe"),
    ("BackupAgent.exe", "BackupUpload.exe"),
]

SYSTEM_PROCESSES = {
    "services.exe", "svchost.exe", "taskhostw.exe", "backgroundTaskHost.exe", "RuntimeBroker.exe",
    "MpCmdRun.exe", "wuauclt.exe", "SearchProtocolHost.exe", "WmiPrvSE.exe", "TiWorker.exe",
    "msiexec.exe", "conhost.exe", "dfsrs.exe", "dns.exe", "srmhost.exe", "sqlservr.exe",
    "sqlceip.exe", "disp+work.exe", "MSExchangeTransport.exe", "EdrManager.exe", "WsusService.exe",
    "spoolsv.exe", "PrintIsolationHost.exe", "BackupAgent.exe", "vssadmin.exe", "robocopy.exe",
    "BackupUpload.exe", "sihost.exe", "ctfmon.exe", "userinit.exe", "rdpclip.exe", "csc.exe",
    "w3wp.exe", "bcp.exe", "cmd.exe",
}  # fmt: skip

IMAGE_DIRS = {
    "chrome.exe": r"C:\Program Files\Google\Chrome\Application",
    "msedge.exe": r"C:\Program Files (x86)\Microsoft\Edge\Application",
    "msedgewebview2.exe": r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\141.0.3537.71",
    "outlook.exe": r"C:\Program Files\Microsoft Office\root\Office16",
    "winword.exe": r"C:\Program Files\Microsoft Office\root\Office16",
    "excel.exe": r"C:\Program Files\Microsoft Office\root\Office16",
    "powerpnt.exe": r"C:\Program Files\Microsoft Office\root\Office16",
    "teams.exe": r"C:\Program Files\WindowsApps\MSTeams_25198.1112.3855.2087_x64__8wekyb3d8bbwe",
    "acrord32.exe": r"C:\Program Files\Adobe\Acrobat DC\Acrobat",
    "code.exe": r"C:\Users\{user}\AppData\Local\Programs\Microsoft VS Code",
    "git.exe": r"C:\Program Files\Git\cmd",
    "git-remote-https.exe": r"C:\Program Files\Git\mingw64\libexec\git-core",
    "node.exe": r"C:\Program Files\nodejs",
    "python.exe": r"C:\Users\{user}\AppData\Local\Programs\Python\Python313",
    "saplogon.exe": r"C:\Program Files\SAP\FrontEnd\SAPGUI",
    "zoom.exe": r"C:\Users\{user}\AppData\Roaming\Zoom\bin",
    "slack.exe": r"C:\Users\{user}\AppData\Local\slack",
    "photoshop.exe": r"C:\Program Files\Adobe\Adobe Photoshop 2026",
    "putty.exe": r"C:\Program Files\PuTTY",
    "OneDrive.exe": r"C:\Program Files\Microsoft OneDrive",
    "WindowsTerminal.exe": r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.23.12811.0_x64__8wekyb3d8bbwe",
    "MpCmdRun.exe": r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25090.3009-0",
    "BackupAgent.exe": r"C:\Program Files\Veeam\Backup Agent",
    "BackupUpload.exe": r"C:\Program Files\Veeam\Backup Agent",
    "EdrManager.exe": r"C:\Program Files\EDR\Manager",
    "sqlservr.exe": r"C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Binn",
    "sqlceip.exe": r"C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Binn",
    "bcp.exe": r"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn",
}
LINUX_DIRS = {
    "bash": "/usr/bin", "python3": "/usr/bin", "curl": "/usr/bin", "logrotate": "/usr/sbin",
    "sshd": "/usr/sbin", "java": "/usr/lib/jvm/java-21-openjdk/bin", "nginx": "/usr/sbin",
    "squid": "/usr/sbin", "openvpn": "/usr/sbin", "prometheus": "/usr/local/bin",
    "check_http": "/usr/lib/nagios/plugins", "gitlab-runner": "/usr/bin", "docker": "/usr/bin",
    "make": "/usr/bin", "gcc": "/usr/bin", "git": "/usr/bin", "systemd-journald": "/lib/systemd",
}  # fmt: skip

COMMAND_LINES: dict[str, list[str]] = {
    "chrome.exe": [
        '"{image}" --type=renderer --lang=en-US --renderer-client-id={n}',
        '"{image}" --type=utility --utility-sub-type=network.mojom.NetworkService',
        '"{image}"',
    ],
    "msedge.exe": ['"{image}" --type=renderer --renderer-client-id={n}', '"{image}"'],
    "outlook.exe": ['"{image}"'],
    "winword.exe": ['"{image}" /n "C:\\Users\\{user}\\Documents\\report-{n}.docx"'],
    "excel.exe": ['"{image}" "C:\\Users\\{user}\\Documents\\budget-{n}.xlsx"', '"{image}"'],
    "powerpnt.exe": ['"{image}" "C:\\Users\\{user}\\Documents\\deck-{n}.pptx"'],
    "acrord32.exe": ['"{image}" "C:\\Users\\{user}\\Downloads\\invoice-{n}.pdf"'],
    "git.exe": [
        "git.exe pull --rebase",
        "git.exe status",
        "git.exe fetch origin",
        "git.exe commit -m wip",
    ],
    "git-remote-https.exe": [
        "git-remote-https.exe origin https://github.com/example-corp/app-{n}.git"
    ],
    "node.exe": ['"{image}" node_modules\\vite\\bin\\vite.js', '"{image}" server.js'],
    "python.exe": [
        '"{image}" -m pytest -q',
        '"{image}" manage.py runserver',
        '"{image}" -m pip list',
    ],
    "powershell.exe": [
        "powershell.exe -NoLogo",
        "powershell.exe -NoProfile -File C:\\Scripts\\inventory-{n}.ps1",
        "powershell.exe -NoProfile -Command Get-Service",
    ],
    "cmd.exe": ['"C:\\Windows\\system32\\cmd.exe"', "cmd.exe /c C:\\Scripts\\cleanup-temp.cmd"],
    "net.exe": ["net.exe user {other} /domain", 'net.exe group "Helpdesk" /domain'],
    "nltest.exe": ["nltest.exe /dsgetdc:corp.example"],
    "ipconfig.exe": ["ipconfig.exe /all", "ipconfig.exe /flushdns"],
    "ping.exe": ["ping.exe -n 4 srv-file-01.corp.example"],
    "mmc.exe": [
        '"C:\\Windows\\system32\\mmc.exe" "C:\\Windows\\system32\\dsa.msc"',
        '"C:\\Windows\\system32\\mmc.exe" "C:\\Windows\\system32\\gpmc.msc"',
    ],
    "mstsc.exe": ['"C:\\Windows\\system32\\mstsc.exe" /v:srv-jump-01.corp.example'],
    "MpCmdRun.exe": ['"{image}" -wdenable', '"{image}" -Scan -ScanType 1'],
    "svchost.exe": [
        "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
        "C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p",
    ],
    "WmiPrvSE.exe": ["C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding"],
    "vssadmin.exe": ["vssadmin.exe create shadow /for=D:", "vssadmin.exe list shadows"],
    "robocopy.exe": ["robocopy.exe \\\\srv-file-0{k}\\share D:\\Backup\\share /MIR /R:1"],
    "BackupUpload.exe": ['"{image}" --target s3://example-corp-offsite --compress'],
    "bcp.exe": ['"{image}" reporting.dbo.sales out D:\\exports\\sales-{n}.dat -T -c'],
    "csc.exe": [
        '"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe" /noconfig /fullpaths @"C:\\Windows\\TEMP\\{n}.cmdline"'
    ],
    "bash": ["/bin/bash -c /etc/cron.hourly/{script}", "-bash"],
    "python3": ["/usr/bin/python3 /opt/scripts/report_{n}.py"],
    "curl": ["curl -fsS http://localhost:8080/health"],
    "docker": ["docker build -t registry.corp.example/app:{n} ."],
    "git": ["git clone https://github.com/example-corp/app-{n}.git"],
    "make": ["make -j8 all"],
}

ADMIN_TOOLS = {"mmc.exe", "powershell.exe", "net.exe", "nltest.exe", "mstsc.exe", "cmd.exe"}
