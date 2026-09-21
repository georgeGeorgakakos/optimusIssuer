#Requires -Version 5.1
<#
.SYNOPSIS
    Build and run optimusIssuer in Docker on Windows.

.DESCRIPTION
    Checks the toolchain, runs the Go tests, builds the image and starts a
    container. Designed to be run from the repository root, from GoLand's
    terminal or an ordinary PowerShell window.

    The key is mounted into the container as a read-only file rather than
    passed as an environment variable, which is how it is handled in
    Kubernetes too. A key passed through the environment appears in
    `docker inspect`, in crash output and in any child process.

.PARAMETER Action
    build    build the image only
    run      build if needed, then start a container
    test     run the Go tests and stop
    stop     stop and remove the container
    logs     follow the container log
    shell    open a shell inside the running container
    clean    remove the container, the image and local build output

.PARAMETER Agent
    OptimusDB agent base URL the service should talk to.
    Default http://host.docker.internal:18001, which reaches an agent running
    on the Windows host from inside the container.

.PARAMETER Port
    Host port to publish. Default 8090.

.PARAMETER KeyFile
    Issuer key file to mount. Default .\dev.key; created if absent.

.PARAMETER OidcIssuer
    Keycloak realm URL. Empty disables operator authentication, which is
    intended for development only and makes the service log a warning on
    every start.

.PARAMETER SkipTests
    Build without running the Go tests first. Not recommended: the
    canonicalisation tests are the ones that catch a credential that will
    not verify inside the agents.

.EXAMPLE
    .\build-and-run.ps1 run

.EXAMPLE
    .\build-and-run.ps1 run -Agent http://193.225.250.240/optimusdb1

.EXAMPLE
    .\build-and-run.ps1 run -OidcIssuer http://193.225.250.240/realms/optimusddc
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('build', 'run', 'test', 'stop', 'logs', 'shell', 'clean')]
    [string]$Action = 'run',

    [string]$Agent      = 'http://host.docker.internal:18001',
    [int]   $Port       = 8090,
    [string]$KeyFile    = '.\dev.key',
    [string]$OidcIssuer = '',
    [string]$Image      = 'optimusissuer',
    [string]$Tag        = 'dev',
    [string]$Container  = 'optimusissuer',
    [switch]$SkipTests,
    [switch]$NoCache
)

$ErrorActionPreference = 'Stop'

# docker, go and npm all write informational text to stderr. With
# $ErrorActionPreference = 'Stop', PowerShell converts any native stderr output
# into a terminating error, so a harmless warning aborts the script. Exit codes
# are checked explicitly after every native call instead.
#   PowerShell 7: the preference variable below disables that behaviour.
#   Windows PowerShell 5.1: the variable is ignored, so each call is wrapped.
$PSNativeCommandUseErrorActionPreference = $false

$script:Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $script:Root

# Run a native command, ignore whatever it writes to stderr, and return its
# exit code. Used for every docker, go and npm invocation.
function Invoke-Native {
    param(
        [Parameter(Mandatory)][string]$File,
        [string[]]$Arguments = @(),
        [switch]$Quiet
    )
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        if ($Quiet) {
            & $File @Arguments 2>&1 | Out-Null
        } else {
            & $File @Arguments 2>&1 | ForEach-Object { Write-Host "   $_" -ForegroundColor DarkGray }
        }
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prev
    }
}

# ── output helpers ──────────────────────────────────────────────────────────
function Write-Step { param($m) Write-Host "`n== $m" -ForegroundColor Cyan }
function Write-Ok   { param($m) Write-Host "   OK  $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "   --  $m" -ForegroundColor Yellow }
function Write-Bad  { param($m) Write-Host "   XX  $m" -ForegroundColor Red }

function Fail {
    param($Message, $Hint)
    Write-Bad $Message
    if ($Hint) { Write-Host "       $Hint" -ForegroundColor DarkGray }
    exit 1
}

# ── preflight ───────────────────────────────────────────────────────────────
function Test-Toolchain {
    param([switch]$NeedGo, [switch]$NeedDocker, [switch]$NeedNode)

    if ($NeedDocker) {
        if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
            Fail 'docker was not found on PATH.' 'Install Docker Desktop and reopen the terminal.'
        }
        if ((Invoke-Native -File 'docker' -Arguments @('info') -Quiet) -ne 0) {
            Fail 'The Docker daemon is not responding.' 'Start Docker Desktop and wait for it to finish starting.'
        }
        Write-Ok 'docker is running'
    }

    if ($NeedGo) {
        if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
            Fail 'go was not found on PATH.' 'Install Go 1.21 or later, or pass -SkipTests to build in Docker only.'
        }
        $v = (go version) -replace '.*go(\d+\.\d+).*', '$1'
        Write-Ok "go $v"
    }

    if ($NeedNode) {
        if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
            Write-Warn 'npm was not found; the frontend will be built inside Docker instead.'
            return $false
        }
        Write-Ok "npm $(npm --version)"
    }
    return $true
}

# ── go.sum ──────────────────────────────────────────────────────────────────
function Initialize-Modules {
    # A go.sum can exist and still be incomplete: `go mod download` fetches
    # modules without recording every transitively imported package. Test the
    # build rather than the file's existence.
    if (Test-Path '.\go.sum') {
        if ((Invoke-Native -File 'go' -Arguments @('build', './...') -Quiet) -eq 0) { return }
        Write-Warn 'go.sum is incomplete; running go mod tidy.'
    } else {
        Write-Step 'Resolving modules'
        Write-Warn 'go.sum is absent; this happens once.'
    }
    if ((Invoke-Native -File 'go' -Arguments @('mod', 'tidy')) -ne 0) {
        Fail 'go mod tidy failed.' 'Check network access to proxy.golang.org, or set GOPROXY.'
    }
    Write-Ok 'modules resolved'
}

# ── frontend ────────────────────────────────────────────────────────────────
# cmd/issuerd/main.go embeds cmd/issuerd/webdist, so `go build` and `go test`
# fail outright when that directory does not exist. Build the real interface
# when npm is available; fall back to a placeholder only when it is not, so the
# Go half can still be compiled and tested on a machine without node.
function Initialize-Webdist {
    $dist = '.\cmd\issuerd\webdist'

    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
        if (Test-Path "$dist\index.html") { return }
        Write-Warn 'npm not found; writing a placeholder interface so the Go build succeeds.'
        Write-Placeholder $dist
        return
    }

    # npm ci needs a lockfile and is the reproducible choice once one exists.
    if (-not (Test-Path '.\web\node_modules')) {
        Write-Step 'Installing frontend dependencies'
        $cmd = if (Test-Path '.\web\package-lock.json') { 'ci' } else { 'install' }
        if ((Invoke-Native -File 'npm' -Arguments @('--prefix', 'web', $cmd)) -ne 0) {
            Write-Warn 'npm install failed; falling back to a placeholder interface.'
            Write-Placeholder $dist
            return
        }
        Write-Ok 'dependencies installed'
    }

    # Rebuild when the sources are newer than the bundle, so an edit in web/src
    # is picked up without having to remember a separate command.
    $needsBuild = $true
    if (Test-Path "$dist\index.html") {
        $built = (Get-Item "$dist\index.html").LastWriteTimeUtc
        $newest = Get-ChildItem '.\web\src', '.\web\index.html', '.\web\vite.config.js' `
                    -Recurse -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
        if ($newest -and $newest.LastWriteTimeUtc -le $built) { $needsBuild = $false }
    }

    if (-not $needsBuild) {
        Write-Ok 'frontend bundle is current'
        return
    }

    Write-Step 'Building the frontend'
    if ((Invoke-Native -File 'npm' -Arguments @('--prefix', 'web', 'run', 'build')) -ne 0) {
        Write-Warn 'The frontend build failed; falling back to a placeholder interface.'
        Write-Warn 'The API is unaffected, but the browser interface will show a placeholder.'
        Write-Placeholder $dist
        return
    }

    if (-not (Test-Path "$dist\index.html")) {
        Write-Warn "npm reported success but $dist\index.html is absent."
        Write-Warn 'Check build.outDir in web/vite.config.js — it must be ../cmd/issuerd/webdist.'
        Write-Placeholder $dist
        return
    }

    $assets = (Get-ChildItem $dist -Recurse -File | Measure-Object).Count
    Write-Ok "frontend built ($assets files)"
}

function Write-Placeholder {
    param([string]$Dist)
    New-Item -ItemType Directory -Path $Dist -Force | Out-Null
    @'
<!doctype html>
<meta charset="utf-8">
<title>optimusIssuer</title>
<p style="font-family:sans-serif;padding:2rem">
  Placeholder interface. Run <code>npm install</code> then
  <code>npm run build</code> in <code>web/</code> to produce the real one.
  The API at <code>/api/v1/issuer</code> is unaffected.
</p>
'@ | Set-Content -Path "$Dist\index.html" -Encoding UTF8
}

# ── actions ─────────────────────────────────────────────────────────────────
function Invoke-Tests {
    Write-Step 'Go tests'
    Test-Toolchain -NeedGo | Out-Null
    Initialize-Modules
    Initialize-Webdist

    if ((Invoke-Native -File 'go' -Arguments @('vet', './...')) -ne 0) {
        Fail 'go vet reported problems.'
    }
    Write-Ok 'go vet clean'

    if ((Invoke-Native -File 'go' -Arguments @('test', './...', '-count=1')) -ne 0) {
        Fail 'Tests failed.' 'A failure in the canonicalisation tests means credentials this service issues will not verify inside the agents.'
    }
    Write-Ok 'tests passed'
}

function Invoke-Build {
    # Build the interface here as well as inside the Dockerfile. Stage 1 of the
    # image can produce an empty directory without failing, which yields a
    # binary that serves 404 at / — building locally first makes that visible.
    Initialize-Webdist

    Write-Step 'Building the image'
    Test-Toolchain -NeedDocker | Out-Null

    $args = @('build', '-t', "${Image}:${Tag}", '.')
    if ($NoCache) { $args += '--no-cache' }

    Write-Host "   docker $($args -join ' ')" -ForegroundColor DarkGray
    if ((Invoke-Native -File 'docker' -Arguments $args) -ne 0) {
        Fail 'The image build failed.' 'The three stages are: npm build, go build, runtime. The log above names which.'
    }

    $size = (docker image inspect "${Image}:${Tag}" --format '{{.Size}}' 2>$null)
    Write-Ok "built ${Image}:${Tag} ($([math]::Round($size / 1MB, 1)) MB)"
}

function Initialize-Key {
    if (Test-Path $KeyFile) {
        Write-Ok "using $KeyFile"
        return
    }
    Write-Step 'Creating a development key'
    Test-Toolchain -NeedGo | Out-Null
    Initialize-Modules
    Initialize-Webdist

    if ((Invoke-Native -File 'go' `
            -Arguments @('run', './cmd/issuerctl', 'keygen', '--out', $KeyFile,
    '--label', 'development')) -ne 0) {
        Fail 'Key generation failed.'
    }

    Write-Warn 'This is a development key. Never use it for a deployment; produce one through the ceremony in section 9 of the design document.'
}

function Invoke-Run {
    Test-Toolchain -NeedDocker | Out-Null

    $imageExists = ((Invoke-Native -File 'docker' `
        -Arguments @('image', 'inspect', "${Image}:${Tag}") -Quiet) -eq 0)
    if (-not $imageExists) {
        Write-Warn 'No image yet; building first.'
        if (-not $SkipTests) { Invoke-Tests }
        Invoke-Build
    }

    Initialize-Key
    $keyPath = (Resolve-Path $KeyFile).Path

    # Stop an earlier container quietly so the script is safe to re-run.
    Invoke-Native -File 'docker' -Arguments @('rm', '-f', $Container) -Quiet | Out-Null

    Write-Step 'Starting the container'

    $runArgs = @(
        'run', '-d',
        '--name', $Container,
        '-p', "${Port}:8090",
        # Mounted as a file, read-only. Not an environment variable: those show
        # up in docker inspect and in crash output.
        '-v', "${keyPath}:/etc/issuer/key/issuer.key:ro",
        '--add-host', 'host.docker.internal:host-gateway',
        # Docker Desktop reports every bind-mounted file as 0777 regardless of
        # its Windows permissions. Development only — a Kubernetes Secret
        # mounted with defaultMode 0400 reports the real mode, so this is never
        # set in a deployment.
        '-e', 'OPTIMUS_ALLOW_INSECURE_KEY_PERMS=1',
        "${Image}:${Tag}",
        '-addr', ':8090',
        '-key', '/etc/issuer/key/issuer.key',
        '-agent', $Agent
    )
    # Pass the flag only when there is a value. PowerShell drops empty strings
    # when splatting to a native command, so '-oidc-issuer', '' arrives as a
    # bare flag and Go's flag package exits 2. The flag's own default is an
    # empty string, which already means "operator authentication disabled".
    if ($OidcIssuer) {
        $runArgs += @('-oidc-issuer', $OidcIssuer, '-oidc-audience', 'optimusissuer')
    }

    if ((Invoke-Native -File 'docker' -Arguments $runArgs -Quiet) -ne 0) {
        Fail 'The container failed to start.' 'Run with -Action logs to see why.'
    }

    Start-Sleep -Seconds 2

    $state = (docker inspect -f '{{.State.Status}}' $Container 2>$null)
    if ($state -ne 'running') {
        Write-Bad "The container is $state. Log follows:"
        docker logs $Container
        Fail 'Start-up failed.' 'A key file with loose permissions is the usual cause; the service refuses to start on one.'
    }
    Write-Ok "container running, published on port $Port"

    # ── health ──────────────────────────────────────────────────────────────
    Write-Step 'Health'
    $url = "http://localhost:$Port/api/v1/issuer/health"
    $health = $null
    foreach ($attempt in 1..10) {
        try {
            # The endpoint returns 503 when the agent is unreachable, which is
            # a correct answer rather than a failure — issuance needs the agent,
            # verification by the agents does not. Invoke-RestMethod throws on
            # any non-2xx, so read the body out of the exception instead.
            $health = Invoke-RestMethod -Uri $url -TimeoutSec 3
            break
        } catch [System.Net.WebException] {
            $resp = $_.Exception.Response
            if ($resp) {
                $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
                $body = $reader.ReadToEnd()
                $reader.Close()
                if ($body) {
                    $health = $body | ConvertFrom-Json
                    break
                }
            }
            Start-Sleep -Milliseconds 700
        } catch {
            Start-Sleep -Milliseconds 700
        }
    }

    if (-not $health) {
        Write-Bad 'The health endpoint did not answer. Log follows:'
        docker logs --tail 40 $Container
        exit 1
    }

    Write-Ok "issuer DID  $($health.issuer_did)"
    if ($health.agent -eq 'reachable') {
        Write-Ok "agent       $Agent"
    } else {
        Write-Warn "agent       $Agent is not reachable"
        Write-Host '       Issuance will fail until it is. Verification by the agents is unaffected.' -ForegroundColor DarkGray
    }

    if (-not $OidcIssuer) {
        Write-Warn 'Operator authentication is DISABLED. Development only.'
    }

    Write-Host ''
    Write-Host '  interface   ' -NoNewline; Write-Host "http://localhost:$Port/" -ForegroundColor White
    Write-Host '  health      ' -NoNewline; Write-Host $url -ForegroundColor White
    Write-Host '  logs        ' -NoNewline; Write-Host ".\build-and-run.ps1 logs" -ForegroundColor White
    Write-Host '  stop        ' -NoNewline; Write-Host ".\build-and-run.ps1 stop" -ForegroundColor White
    Write-Host ''
}

function Invoke-Stop {
    Write-Step 'Stopping'
    if ((Invoke-Native -File 'docker' -Arguments @('rm', '-f', $Container) -Quiet) -eq 0) {
        Write-Ok 'container removed'
    } else {
        Write-Warn 'no container was running'
    }
}

function Invoke-Logs {
    docker logs -f $Container
}

function Invoke-Shell {
    Write-Warn 'The runtime image is Alpine and runs as UID 10001; only a limited shell is available.'
    docker exec -it $Container /bin/sh
}

function Invoke-Clean {
    Write-Step 'Cleaning'
    Invoke-Native -File 'docker' -Arguments @('rm', '-f', $Container) -Quiet | Out-Null
    Invoke-Native -File 'docker' -Arguments @('rmi', "${Image}:${Tag}") -Quiet | Out-Null
    Remove-Item -Recurse -Force '.\bin', '.\cmd\issuerd\webdist' -ErrorAction SilentlyContinue
    Write-Ok 'container, image and build output removed'
    Write-Warn "$KeyFile was left in place. Delete it yourself if you mean to."
}

# ── dispatch ────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host 'optimusIssuer' -ForegroundColor White -NoNewline
Write-Host "  —  $Action" -ForegroundColor DarkGray

switch ($Action) {
    'test'  { Invoke-Tests }
    'build' { if (-not $SkipTests) { Invoke-Tests }; Invoke-Build }
    'run'   { if (-not $SkipTests) { Invoke-Tests }; Invoke-Build; Invoke-Run }
    'stop'  { Invoke-Stop }
    'logs'  { Invoke-Logs }
    'shell' { Invoke-Shell }
    'clean' { Invoke-Clean }
}
