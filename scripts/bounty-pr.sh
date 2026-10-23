#!/usr/bin/env bash
# bounty-pr.sh — 赏金 PR 自动化
#
# 用法:
#   bounty-pr.sh start  <owner/repo> <issue-number>   领取任务: 竞争度体检 → fork → clone → 建分支 → 生成任务简报
#   bounty-pr.sh submit <workdir> "<PR标题>" [body文件]  交付: DCO 签名提交 → push 到 fork → 尝试开 PR (失败则输出一键链接)
#
# 设计立场:
#   - 机械流程全自动, 代码实现留给人和 agent —— 纯 AI 无人值守交付会被维护者拒收
#   - 所有提交强制 DCO (Signed-off-by), MisakaNet 的教训
#   - 提交前展示将包含的文件清单, 防止误提交本地敏感文件

set -euo pipefail

# 第三方仓库写权限走 device-flow PAT (public_repo); 沙箱默认 ghu_ token 仅自己仓库可写
if [ -z "${GH_TOKEN:-}" ] && [ -s /workspace/.gh-pat ]; then
  GH_TOKEN=$(cat /workspace/.gh-pat); export GH_TOKEN
fi

GH_USER="${GH_USER:-tangfei7777-cell}"
WORKROOT="${WORKROOT:-/workspace/.bounty-work}"
BLACKLIST="SecureBananaLabs/bug-bounty ClankerNation/OpenAgents limitlessprojects/Go-Hybrid watney-ai/open-source-bounties"

die() { echo "✗ $*" >&2; exit 1; }
info() { echo "→ $*"; }
ok()   { echo "✓ $*"; }

# --------------------------------------------------------------------------
cmd_start() {
  local repo="${1:?用法: bounty-pr.sh start <owner/repo> <issue>}" issue="${2:?缺少 issue 编号}"

  case " $BLACKLIST " in *" $repo "*) die "$repo 在黑名单内 (低质量/已死来源), 拒绝接单";; esac
  [[ "$repo" == */* ]] || die "仓库格式应为 owner/repo"

  # 1. 竞争度体检: 已有的关联 PR 和 /attempt 数量
  info "竞争度体检: $repo#$issue"
  local attempts linked_prs owner_reply created
  attempts=$(gh issue view "$issue" -R "$repo" --json comments --jq '[.comments[] | select(.body | test("/attempt|/claim"; "i"))] | length' 2>/dev/null || echo 0)
  linked_prs=$(gh issue view "$issue" -R "$repo" --json comments --jq '[.comments[] | select(.body | test("pull/[0-9]+|PR #[0-9]"))] | length' 2>/dev/null || echo 0)
  owner_reply=$(gh issue view "$issue" -R "$repo" --json comments --jq '[.comments[] | select(.authorAssociation == "OWNER")] | length' 2>/dev/null || echo 0)
  created=$(gh issue view "$issue" -R "$repo" --json createdAt --jq .createdAt 2>/dev/null || echo unknown)

  echo "    /attempt 认领: ${attempts}  |  已提交 PR: ${linked_prs}  |  owner 回复: ${owner_reply} 条  |  创建于: ${created}"
  if [ "$linked_prs" -ge 5 ]; then
    echo "    ⚠ 已有 ${linked_prs} 个竞争 PR, 红海。仅当确认自己方案显著更优时继续。"
  fi
  if [ "$owner_reply" -eq 0 ]; then
    echo "    ⚠ owner 从未回复: 付款条款未经确认, 有白嫖风险。建议先在 issue 下确认赏金托管。"
  fi

  # 2. fork (幂等: 已 fork 则跳过)
  info "fork $repo"
  gh repo fork "$repo" --clone=false >/dev/null 2>&1 && ok "fork 就绪: ${GH_USER}/${repo#*/}" || ok "fork 已存在: ${GH_USER}/${repo#*/}"

  # 3. clone + 分支
  local name="${repo#*/}"
  local dir="${WORKROOT}/${name}-issue-${issue}"
  rm -rf "$dir"
  info "浅克隆 fork → $dir"
  gh repo clone "${GH_USER}/${repo#*/}" "$dir" -- --depth 50 --quiet
  git -C "$dir" remote add upstream "https://github.com/${repo}.git" 2>/dev/null || true
  git -C "$dir" fetch upstream main --quiet 2>/dev/null || git -C "$dir" fetch upstream master --quiet
  local base
  base=$(git -C "$dir" rev-parse --verify --quiet upstream/main >/dev/null 2>&1 && echo upstream/main || echo upstream/master)

  # 与上游同步 (fork 可能落后)
  git -C "$dir" checkout -B "bounty/issue-${issue}" "$base" --quiet
  ok "分支 bounty/issue-${issue} 建于 ${base} 最新提交"

  # 4. 生成任务简报
  local brief="${dir}/BOUNTY-BRIEF.md"
  {
    echo "# 赏金任务简报 — ${repo}#${issue}"
    echo
    echo "- Issue: https://github.com/${repo}/issues/${issue}"
    echo "- 创建: ${created} | /attempt: ${attempts} | 竞争 PR: ${linked_prs}"
    echo
    echo "## Issue 原文"
    echo
    gh issue view "$issue" -R "$repo" --json title,body --jq '"## " + .title + "\n\n" + .body'
    echo
    echo "## Owner/维护者评论 (条款与验收标准)"
    echo
    gh issue view "$issue" -R "$repo" --json comments --jq '.comments[] | select(.authorAssociation == "OWNER" or .authorAssociation == "MEMBER") | "### " + .author.login + " (" + .authorAssociation + ")\n\n" + .body' 2>/dev/null || echo "(无)"
    echo
    echo "## 交付清单 (提交前逐项打勾)"
    echo "- [ ] 验收标准逐条满足"
    echo "- [ ] 新增测试覆盖核心行为"
    echo "- [ ] CI 全绿 (含 DCO)"
    echo "- [ ] PR 描述含 Fixes #${issue}"
    echo "- [ ] 本地真实环境验证过 (AI 输出需人工复核, owner 明确要求)"
  } > "$brief"
  ok "简报已生成: $brief"

  # 5. 提交身份配置 (DCO 需要)
  git -C "$dir" config user.name  "$(git config user.name  || echo "$GH_USER")"
  git -C "$dir" config user.email "$(git config user.email || echo "${GH_USER}@users.noreply.github.com")"

  echo
  ok "工作区就绪。实现代码后执行:"
  echo "    $0 submit \"$dir\" \"<PR标题>\" [body.md]"
}

# --------------------------------------------------------------------------
cmd_submit() {
  local dir="${1:?用法: bounty-pr.sh submit <workdir> <标题> [body文件]}"
  local title="${2:?缺少 PR 标题}"
  local body_file="${3:-}"

  [[ -d "$dir/.git" ]] || die "$dir 不是 git 工作区"
  [ -z "$(git -C "$dir" status --porcelain)" ] && die "没有待提交的改动"

  local repo branch
  repo=$(git -C "$dir" remote get-url upstream | sed -E 's#https://github.com/##; s#\.git$##')
  branch=$(git -C "$dir" rev-parse --abbrev-ref HEAD)
  local issue="${branch##*issue-}"

  # 展示文件清单 — 防误提交
  echo "将提交以下文件:"
  git -C "$dir" status --short
  echo
  read -r -p "确认提交? [y/N] " ans
  [[ "${ans:-n}" == "y" ]] || die "已取消"

  # DCO 签名提交
  git -C "$dir" add -A
  git -C "$dir" commit -s -m "${title}" --quiet
  ok "已提交 (含 Signed-off-by)"

  info "push 到 fork: ${GH_USER}:${branch}"
  git -C "$dir" push -u origin "$branch" --quiet
  ok "已推送"

  # 尝试直接开 PR; 沙箱 token 对第三方仓库可能无写权限 → 403 时给一键链接
  local body_args=()
  if [ -n "$body_file" ]; then
    body_args=(--body-file "$body_file")
  else
    body_args=(--body "Closes #${issue}")
  fi

  info "创建 PR → ${repo}"
  if gh pr create -R "$repo" --head "${GH_USER}:${branch}" --base main --title "$title" "${body_args[@]}" 2>/tmp/pr-err; then
    ok "PR 已创建"
  else
    echo "    ✗ 沙箱 token 权限不足以直接开 PR ($(head -c120 /tmp/pr-err))"
    echo "    一键开 PR (浏览器打开, 确认后点 Create):"
    echo "    https://github.com/${repo}/compare/main...${GH_USER}:${branch}?expand=1&title=${title// /%20}"
    if [[ "$body_file" != "" ]]; then
      echo "    (PR 描述请粘贴: $body_file)"
    fi
  fi

  echo
  ok "提醒: PR 合并后 — Algora 类任务自动入账; owner 直付类在 issue 里回复收款方式。"
}

# --------------------------------------------------------------------------
case "${1:-}" in
  start)  shift; cmd_start "$@" ;;
  submit) shift; cmd_submit "$@" ;;
  *) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
