# Git Push Guide

Steps to push this project to a GitHub repository.

## Prerequisites

- A GitHub account
- A repository created on GitHub (e.g., `your-username/wazuh-ai-correlation-engine`)

## 1. Initialize Git (first time only)

```bash
git init
```

## 2. Set up `.gitignore`

Make sure sensitive files are excluded. The project already has a `.gitignore` with these essentials:

- `.env` — API keys and secrets
- `*.db`, `*.db-shm`, `*.db-wal` — Database files
- `__pycache__/`, `.pytest_cache/`, `.ruff_cache/` — Cache directories
- `nohup.out` — Runtime logs
- `data/reports/`, `data/alerts/*.json`, `data/geoip/*.mmdb` — Runtime data

## 3. Set author identity (first time only)

```bash
git config user.email "your-email@example.com"
git config user.name "Your Name"
```

## 4. Connect to remote repository

### Option A — SSH (recommended)

Generate an SSH key:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
```

Add it to your GitHub account at **https://github.com/settings/keys**.

If port 22 is blocked, configure SSH to use port 443:

```bash
cat >> ~/.ssh/config << 'EOF'
Host github.com
  HostName ssh.github.com
  Port 443
  User git
EOF
ssh-keyscan -t ed25519 -p 443 ssh.github.com > ~/.ssh/known_hosts
```

Set the remote URL:

```bash
git remote add origin git@github.com:YOUR_USERNAME/wazuh-ai-correlation-engine.git
```

### Option B — Personal Access Token

Create a token at **https://github.com/settings/tokens** with `repo` scope, then:

```bash
git remote add origin https://TOKEN@github.com/YOUR_USERNAME/wazuh-ai-correlation-engine.git
```

## 5. Stage, commit, and push

```bash
git add .
git commit -m "Initial commit: AI-powered correlation engine for Wazuh SIEM"
git push -u origin master
```

The `-u` flag sets upstream tracking so future pushes can just use `git push`.

## 6. Future commits

```bash
git add .
git commit -m "Description of changes"
git push
```
