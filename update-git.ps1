<#
.SYNOPSIS
    Stage, scan, commit and push the optimusIssuer repository.

.DESCRIPTION
    Wraps the commit/push cycle with the two safeguards this repository needs:

      1. A secret scan of the STAGED content before anything is committed.
         This repository is PUBLIC. A private key committed once stays in the
         history forever and must be rotated, not merely deleted. The scan
         mirrors the CI job, so a violation fails here in two seconds instead
         of in CI two minutes later.

      2. A rebase-with-autostash sync before pushing, which is what avoids the
         "Updates were rejected because the tip of your current branch is
         behind" and "cannot pull with rebase: You have unstaged changes"
         errors.

    Every git call goes through Invoke-Git. That is not decoration: git writes
    normal progress output to stderr, and under $ErrorActionPreference = 'Stop'
    PowerShell turns native stderr into a terminating error. A script that
    calls git directly will appear to fail on a completely successful push.

.PARAMETER Message
    The commit message. Required unless -DryRun or -Status is used.

.PARAMETER Branch
    Branch to push to. Defaults to the current branch.

.PARAMETER NoPull
    Skip the rebase sync. Only sensible when you know the remote has not moved.

.PARAMETER NoPush
    Commit locally, do not push.

.PARAMETER Force
    Skip the confirmation prompt. The secret scan still runs and still blocks;
    -Force never overrides it.

.PARAMETER DryRun
    Show exactly what would be staged, scanned and committed. Changes nothing.

.PARAMETER Status
    Print repository state and exit.

.EXAMPLE
    .\update-git.ps1 "docs: add CONCEPTS.md and issuerctl README"

.EXAMPLE
    .\update-git.ps1 -DryRun

.EXAMPLE
    .\update-git.ps1 "fix: embed directive in main.go" -Force
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string] $Message,

    [string] $Branch,
    [switch] $NoPull,
    [switch] $NoPush,
    [switch] $Force,
    [switch] $DryRun,
    [switch] $Status
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

# ── output helpers ──────────────────────────────────────────────────────────

function Write-Head { param([string]$t) Write-Host "`n== $t" -ForegroundColor Cyan }
function Write-Ok   { param([string]$t) Write-Host "   OK  $t" -ForegroundColor Green }
function Write-Warn { param([string]$t) Write-Host "   !!  $t" -ForegroundColor Yellow }
function Write-Bad  { param([string]$t) Write-Host "   XX  $t" -ForegroundColor Red }
function Write-Dim  { param([string]$t) Write-Host "       $t" -ForegroundColor DarkGray }

function Stop-Script {
    param([string]$Reason, [string[]]$Hints = @())
    Write-Bad $Reason
    foreach ($h in $Hints) { Write-Dim $h }
    exit 1
}

# ── git invocation ──────────────────────────────────────────────────────────

<#
    Runs git and returns @{ Output = <string[]>; Code = <int> }.

    $ErrorActionPreference is lowered to 'Continue' for the duration of the
    call. Without this, git's ordinary stderr chatter ("Switched to branch",
    push progress, rebase notices) is promoted to a terminating error and the
    script dies on success. $LASTEXITCODE is the only reliable verdict.
#>
function Invoke-Git {
    param(
        [Parameter(Mandatory)][string[]] $Arguments,
        [switch] $Show
    )
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & git @Arguments 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
        if ($Show -and $out) { $out | ForEach-Object { Write-Dim $_ } }
        return [pscustomobject]@{ Output = @($out); Code = $code }
    }
    finally { $ErrorActionPreference = $prev }
}

function Invoke-GitOrDie {
    param([Parameter(Mandatory)][string[]] $Arguments, [string] $What)
    $r = Invoke-Git -Arguments $Arguments -Show
    if ($r.Code -ne 0) {
        Stop-Script "git $($Arguments -join ' ') failed (exit $($r.Code))." @(
        if ($What) { $What } else { '' }
        )
    }
    return $r
}

# ── the secret scan ─────────────────────────────────────────────────────────

# Paths that must never be tracked. These mirror .gitignore and the CI job.
$BlockedPaths = @(
    @{ Pattern = '\.key$';                  Why = 'private key file' }
    @{ Pattern = '\.pem$';                  Why = 'PEM key or certificate' }
    @{ Pattern = '\.(pfx|p12)$';            Why = 'PKCS#12 key store' }
    @{ Pattern = '\.vc\.json$';             Why = 'issued credential; CI rejects tracked credentials' }
    @{ Pattern = '(^|/)secret\.ya?ml$';     Why = 'Kubernetes Secret with real data' }
    @{ Pattern = '(^|/)id_(rsa|ed25519)$';  Why = 'SSH private key' }
    @{ Pattern = '(^|/)\.env$';             Why = 'environment file, commonly holds secrets' }
)

# A scanner whose source contains its own detection patterns will flag itself.
# The PEM header below is therefore ASSEMBLED rather than written out, so that
# no line of this file is a literal key header. Keep it that way when adding
# patterns: never paste a complete real-world secret marker as a literal.
$pemOpen = '-----BEGIN '
$pemTail = 'PRIV' + 'ATE KEY-----'

# Content that must never appear in a diff, whatever the file is called.
$BlockedContent = @(
    @{ Name = 'Ed25519 private key material'
    Regex = '"privateKeyMultibase"\s*:\s*"z[1-9A-HJ-NP-Za-km-z]{40,}"' }
    @{ Name = 'PEM private key block'
    Regex = "$pemOpen[A-Z0-9 ]*$pemTail" }
    @{ Name = 'SSH private key block'
    Regex = "${pemOpen}OPENSSH $pemTail" }
    @{ Name = 'AWS access key id'
    Regex = 'AKIA[0-9A-Z]{16}' }
    @{ Name = 'GitHub token'
    Regex = 'gh[pousr]_[A-Za-z0-9]{36,}' }
    @{ Name = 'Populated Kubernetes Secret key'
    Regex = '(?m)^\+\s*(issuer\.key|tls\.key|token)\s*:\s*[A-Za-z0-9+/=]{24,}' }
)

# Documentation legitimately shows what a key file looks like. A line carrying
# this marker is skipped by the content scan. Use it sparingly, and never on a
# line holding real material — the marker suppresses the check, it does not
# make the line safe.
$AllowMarker = 'secret-scan:allow'

# Tracked but questionable. Warned about, not blocked.
$WarnPaths = @(
    @{ Pattern = '(^|/)issuers\.json$'
    Why = 'genesis trust list; public data, but deployment specific' }
    @{ Pattern = '(^|/)\.\$.*\.bkp$'
    Why = 'draw.io backup/lock file; add ".$*.bkp" to .gitignore' }
    @{ Pattern = '\.(bak|tmp|orig|swp)$'
    Why = 'editor scratch file' }
)

function Test-StagedContent {
    <#
        Scans what is actually staged, not the working tree. Returns a list of
        findings; an empty list means clean.
    #>
    $findings = @()

    $names = (Invoke-Git -Arguments @('diff', '--cached', '--name-only')).Output |
            Where-Object { $_ -and $_.Trim() }

    foreach ($n in $names) {
        foreach ($b in $BlockedPaths) {
            if ($n -match $b.Pattern) {
                $findings += [pscustomobject]@{
                    Level = 'BLOCK'; Where = $n; What = $b.Why
                }
            }
        }
        foreach ($w in $WarnPaths) {
            if ($n -match $w.Pattern) {
                $findings += [pscustomobject]@{
                    Level = 'WARN'; Where = $n; What = $w.Why
                }
            }
        }
    }

    # Added lines only. -U0 keeps context out of the scan so an unchanged
    # neighbouring line cannot trip it.
    $diff = (Invoke-Git -Arguments @('diff', '--cached', '-U0', '--no-color')).Output
    $file = '(staged diff)'
    foreach ($line in $diff) {
        if ($line -match '^\+\+\+ b/(.+)$') { $file = $Matches[1]; continue }
        if ($line -notmatch '^\+')          { continue }

        # An explicit allowlist marker on the line suppresses the check.
        if ($line -match [regex]::Escape($AllowMarker)) { continue }

        foreach ($c in $BlockedContent) {
            if ($line -match $c.Regex) {
                $findings += [pscustomobject]@{
                    Level = 'BLOCK'; Where = $file; What = $c.Name
                }
            }
        }
    }

    return $findings
}

function Test-GitIgnore {
    if (-not (Test-Path '.gitignore')) {
        Write-Warn 'no .gitignore in this repository'
        return
    }
    $ig = Get-Content '.gitignore' -Raw
    $required = @('*.key', '*.vc.json', '*.pem', 'issuers.json')
    $missing = $required | Where-Object { $ig -notmatch [regex]::Escape($_) }
    if ($missing) {
        Write-Warn "these patterns are not in .gitignore: $($missing -join ', ')"
        Write-Dim  'Add them before the first key ever lands in this directory.'
    } else {
        Write-Ok '.gitignore covers key material'
    }
}

# ── preflight ───────────────────────────────────────────────────────────────

Write-Host ''
Write-Host 'optimusIssuer  —  git update' -ForegroundColor White

Write-Head 'Repository'

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Stop-Script 'git is not on PATH.' @('Install Git for Windows, then reopen the terminal.')
}

$inside = Invoke-Git -Arguments @('rev-parse', '--is-inside-work-tree')
if ($inside.Code -ne 0) {
    Stop-Script 'This directory is not a git repository.' @(
        'cd to the repository root, or run: git init'
    )
}

$root = (Invoke-Git -Arguments @('rev-parse', '--show-toplevel')).Output[0]
Set-Location $root
Write-Ok "root $root"

$current = (Invoke-Git -Arguments @('rev-parse', '--abbrev-ref', 'HEAD')).Output[0]
if ($current -eq 'HEAD') {
    Stop-Script 'HEAD is detached; there is no branch to push.' @(
        'git switch -c my-branch      # keep the work on a new branch',
        'git switch main              # or discard it and go back'
    )
}
if (-not $Branch) { $Branch = $current }
Write-Ok "branch $current"

$remotes = (Invoke-Git -Arguments @('remote')).Output | Where-Object { $_ }
if (-not $remotes) {
    Stop-Script 'No remote is configured.' @(
        'git remote add origin https://github.com/georgeGeorgakakos/optimusIssuer.git'
    )
}
$originUrl = (Invoke-Git -Arguments @('remote', 'get-url', 'origin')).Output[0]
Write-Ok "origin $originUrl"

# An in-progress rebase or merge must be resolved before anything else.
$gitDir = (Invoke-Git -Arguments @('rev-parse', '--git-dir')).Output[0]
foreach ($state in @('rebase-merge', 'rebase-apply', 'MERGE_HEAD', 'CHERRY_PICK_HEAD')) {
    if (Test-Path (Join-Path $gitDir $state)) {
        Stop-Script "A previous operation is unfinished ($state)." @(
            'Resolve the conflicts and: git rebase --continue',
            'or abandon it entirely:     git rebase --abort'
        )
    }
}

Test-GitIgnore

# ── status ──────────────────────────────────────────────────────────────────

Write-Head 'Changes'

$porcelain = (Invoke-Git -Arguments @('status', '--porcelain')).Output |
        Where-Object { $_ -and $_.Trim() }

if (-not $porcelain) {
    Write-Ok 'working tree is clean; nothing to commit'
    if ($Status -or $DryRun) { exit 0 }
    # Still worth checking whether local commits need pushing.
    $ahead = (Invoke-Git -Arguments @('rev-list', '--count', '@{u}..HEAD')).Output[0]
    if ($ahead -and [int]$ahead -gt 0 -and -not $NoPush) {
        Write-Warn "$ahead local commit(s) not yet pushed"
    } else {
        exit 0
    }
} else {
    foreach ($line in $porcelain) {
        $code = $line.Substring(0, 2)
        $path = $line.Substring(3)
        $label = switch -Regex ($code.Trim()) {
            '^\?\?$' { 'new      ' }
            '^A'     { 'added    ' }
            '^M|^.M' { 'modified ' }
            '^D|^.D' { 'deleted  ' }
            '^R'     { 'renamed  ' }
            default  { "$code       " }
        }
        Write-Dim "$label $path"
    }
    Write-Ok "$($porcelain.Count) path(s) changed"
}

if ($Status) { exit 0 }

# ── stage ───────────────────────────────────────────────────────────────────

Write-Head 'Staging and scanning'

if ($porcelain) {
    Invoke-GitOrDie -Arguments @('add', '-A') | Out-Null
    Write-Ok 'staged'
}

$findings = Test-StagedContent
$blocks = @($findings | Where-Object { $_.Level -eq 'BLOCK' })
$warns  = @($findings | Where-Object { $_.Level -eq 'WARN'  })

foreach ($w in $warns) { Write-Warn "$($w.Where) — $($w.What)" }

if ($blocks.Count -gt 0) {
    # Unstage so the repository is left exactly as it was found.
    Invoke-Git -Arguments @('reset') | Out-Null
    Write-Host ''
    Write-Bad 'SECRET SCAN FAILED — nothing was committed, nothing staged.'
    foreach ($b in $blocks) {
        Write-Host "       $($b.Where)" -ForegroundColor Red
        Write-Dim "  $($b.What)"
    }
    Write-Host ''
    Write-Dim 'This repository is public. Remove the file or the secret, add the'
    Write-Dim 'pattern to .gitignore, and run this script again:'
    Write-Dim ''
    Write-Dim '    git rm --cached <path>'
    Write-Dim '    Add-Content .gitignore ''<pattern>'''
    Write-Dim ''
    Write-Dim 'If such a file was EVER pushed, deleting it now is not enough.'
    Write-Dim 'It remains in the history and the key must be rotated.'
    exit 1
}
Write-Ok 'secret scan clean'

if ($DryRun) {
    Write-Head 'Dry run'
    Write-Dim 'Would commit the staged paths above, then rebase onto origin and push.'
    Invoke-Git -Arguments @('reset') | Out-Null
    Write-Ok 'unstaged again; nothing was changed'
    exit 0
}

# ── confirm ─────────────────────────────────────────────────────────────────

if (-not $Message) {
    Stop-Script 'A commit message is required.' @(
        '.\update-git.ps1 "docs: add CONCEPTS.md"',
        '.\update-git.ps1 -DryRun        # to see what would be committed'
    )
}

if (-not $Force) {
    Write-Host ''
    Write-Host "   commit : $Message"
    Write-Host "   branch : $Branch"
    Write-Host "   remote : $originUrl"
    $answer = Read-Host '   proceed? [y/N]'
    if ($answer -notmatch '^(y|yes)$') {
        Invoke-Git -Arguments @('reset') | Out-Null
        Write-Warn 'cancelled; staging undone'
        exit 0
    }
}

# ── commit ──────────────────────────────────────────────────────────────────

Write-Head 'Committing'

$staged = (Invoke-Git -Arguments @('diff', '--cached', '--name-only')).Output |
        Where-Object { $_ -and $_.Trim() }

if ($staged) {
    $r = Invoke-Git -Arguments @('commit', '-m', $Message) -Show
    if ($r.Code -ne 0) {
        Stop-Script 'Commit failed.' @(
            'If git asks who you are, set your identity once:',
            '  git config --global user.name  "George Georgakakos"',
            '  git config --global user.email "george.georgakakos@gmail.com"'
        )
    }
    $sha = (Invoke-Git -Arguments @('rev-parse', '--short', 'HEAD')).Output[0]
    Write-Ok "committed $sha"
} else {
    Write-Ok 'nothing new to commit'
}

# ── sync ────────────────────────────────────────────────────────────────────

if (-not $NoPull) {
    Write-Head 'Syncing with origin'

    $fetch = Invoke-Git -Arguments @('fetch', 'origin') -Show
    if ($fetch.Code -ne 0) {
        Stop-Script 'Could not reach origin.' @(
            'Check the network, and that your credentials are still valid.'
        )
    }

    $hasUpstream = (Invoke-Git -Arguments @('rev-parse', '--abbrev-ref', "$Branch@{u}")).Code -eq 0

    if ($hasUpstream) {
        $behind = (Invoke-Git -Arguments @('rev-list', '--count', "HEAD..$Branch@{u}")).Output[0]
        if ($behind -and [int]$behind -gt 0) {
            Write-Dim "origin is $behind commit(s) ahead; rebasing"

            # --autostash is what prevents "cannot pull with rebase: You have
            # unstaged changes"; it shelves and restores them around the rebase.
            $rb = Invoke-Git -Arguments @('pull', '--rebase', '--autostash', 'origin', $Branch) -Show
            if ($rb.Code -ne 0) {
                Write-Host ''
                Stop-Script 'Rebase stopped, most likely on a conflict.' @(
                    'Your commit is safe. Either resolve and continue:',
                    '  git status                 # see the conflicted files',
                    '  git add <file>',
                    '  git rebase --continue',
                    'or put everything back as it was:',
                    '  git rebase --abort'
                )
            }
            Write-Ok 'rebased onto origin'
        } else {
            Write-Ok 'already up to date with origin'
        }
    } else {
        Write-Warn "branch '$Branch' has no upstream yet; it will be set on push"
    }
}

# ── push ────────────────────────────────────────────────────────────────────

if ($NoPush) {
    Write-Head 'Done'
    Write-Ok 'committed locally; push skipped (-NoPush)'
    exit 0
}

Write-Head 'Pushing'

$hasUpstream = (Invoke-Git -Arguments @('rev-parse', '--abbrev-ref', "$Branch@{u}")).Code -eq 0
$pushArgs = if ($hasUpstream) { @('push', 'origin', $Branch) }
else              { @('push', '-u', 'origin', $Branch) }

$push = Invoke-Git -Arguments $pushArgs -Show
if ($push.Code -ne 0) {
    $text = $push.Output -join "`n"
    if ($text -match 'non-fast-forward|fetch first|behind its remote') {
        Stop-Script 'Push rejected: origin has commits you do not have.' @(
            'Run this script again — the sync step will rebase you on top.',
            'It was skipped this time only if you passed -NoPull.'
        )
    }
    if ($text -match 'Authentication failed|could not read Username|403') {
        Stop-Script 'Push rejected: authentication failed.' @(
            'GitHub no longer accepts account passwords over HTTPS.',
            'Use a personal access token as the password, or switch to SSH:',
            '  git remote set-url origin git@github.com:georgeGeorgakakos/optimusIssuer.git'
        )
    }
    if ($text -match 'protected branch|pre-receive hook declined') {
        Stop-Script 'Push rejected by a branch protection rule.' @(
            'Open a pull request from a feature branch instead.'
        )
    }
    Stop-Script "Push failed (exit $($push.Code))."
}

Write-Ok "pushed to origin/$Branch"

# ── summary ─────────────────────────────────────────────────────────────────

$sha  = (Invoke-Git -Arguments @('rev-parse', '--short', 'HEAD')).Output[0]
$web  = $originUrl -replace '\.git$', '' -replace '^git@github\.com:', 'https://github.com/'

Write-Head 'Done'
Write-Ok "origin/$Branch is now at $sha"
Write-Dim "$web/commits/$Branch"
Write-Dim "$web/actions        # the CI run for this push"
Write-Host ''
