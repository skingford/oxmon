#!/bin/bash

# 1. 安装 Oh My Zsh (如果未安装)
if [ ! -d "$HOME/.oh-my-zsh" ]; then
    echo "正在安装 Oh My Zsh..."
    sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
else
    echo "Oh My Zsh 已存在，跳过..."
fi

ZSH_CUSTOM=${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}

# 2. 安装插件：zsh-autosuggestions (自动建议，类似命令记忆)
if [ ! -d "$ZSH_CUSTOM/plugins/zsh-autosuggestions" ]; then
    echo "正在下载 zsh-autosuggestions..."
    git clone https://github.com/zsh-users/zsh-autosuggestions $ZSH_CUSTOM/plugins/zsh-autosuggestions
else
    echo "zsh-autosuggestions 已存在，跳过..."
fi

# 3. 安装插件：zsh-syntax-highlighting (命令语法高亮)
if [ ! -d "$ZSH_CUSTOM/plugins/zsh-syntax-highlighting" ]; then
    echo "正在下载 zsh-syntax-highlighting..."
    git clone https://github.com/zsh-users/zsh-syntax-highlighting.git $ZSH_CUSTOM/plugins/zsh-syntax-highlighting
else
    echo "zsh-syntax-highlighting 已存在，跳过..."
fi

# 4. 安装 autojump（或 z）与 fzf
# macOS 优先使用 Homebrew 安装
if command -v brew >/dev/null 2>&1; then
    if ! command -v autojump >/dev/null 2>&1; then
        echo "正在通过 Homebrew 安装 autojump..."
        brew install autojump
    else
        echo "autojump 已存在，跳过..."
    fi

    if ! command -v fzf >/dev/null 2>&1; then
        echo "正在通过 Homebrew 安装 fzf..."
        brew install fzf
        echo "正在安装 fzf 的 shell 扩展..."
        $(brew --prefix)/opt/fzf/install --key-bindings --completion --no-update-rc
    else
        echo "fzf 已存在，跳过..."
    fi
else
    echo "未检测到 Homebrew，跳过 autojump 和 fzf 安装。"
    echo "请手动安装 autojump 和 fzf。"
fi

# 5. 安装 Powerlevel10k 主题
if [ ! -d "$ZSH_CUSTOM/themes/powerlevel10k" ]; then
    echo "正在下载 Powerlevel10k 主题..."
    git clone --depth=1 https://github.com/romkatv/powerlevel10k.git $ZSH_CUSTOM/themes/powerlevel10k
else
    echo "Powerlevel10k 主题已存在，跳过..."
fi

# 6. 激活配置
echo "正在配置 .zshrc..."

# 备份原配置
cp ~/.zshrc ~/.zshrc.bak

# 设置主题为 Powerlevel10k
if grep -q "^ZSH_THEME=" ~/.zshrc; then
    sed -i '' 's/^ZSH_THEME=.*/ZSH_THEME="powerlevel10k\/powerlevel10k"/g' ~/.zshrc
else
    echo 'ZSH_THEME="powerlevel10k/powerlevel10k"' >> ~/.zshrc
fi

# 使用 sed 替换插件列表
# 默认包含 git, 增加 z, zsh-autosuggestions, zsh-syntax-highlighting, autojump, fzf
if grep -q "^plugins=" ~/.zshrc; then
    sed -i '' 's/^plugins=.*/plugins=(git z zsh-autosuggestions zsh-syntax-highlighting autojump fzf)/g' ~/.zshrc
else
    echo "plugins=(git z zsh-autosuggestions zsh-syntax-highlighting autojump fzf)" >> ~/.zshrc
fi

echo "✅ 安装完成！"
echo "首次启动时，Powerlevel10k 会引导你进行配置向导。"
echo "请执行 'source ~/.zshrc' 或重启 iTerm2 使配置生效。"