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
fi

# 3. 安装插件：zsh-syntax-highlighting (命令语法高亮)
if [ ! -d "$ZSH_CUSTOM/plugins/zsh-syntax-highlighting" ]; then
    echo "正在下载 zsh-syntax-highlighting..."
    git clone https://github.com/zsh-users/zsh-syntax-highlighting.git $ZSH_CUSTOM/plugins/zsh-syntax-highlighting
fi

# 4. 激活配置
echo "正在配置 .zshrc..."

# 备份原配置
cp ~/.zshrc ~/.zshrc.bak

# 使用 sed 替换插件列表
# 默认包含 git, 增加 z, zsh-autosuggestions, zsh-syntax-highlighting
sed -i '' 's/plugins=(git)/plugins=(git z zsh-autosuggestions zsh-syntax-highlighting)/g' ~/.zshrc

echo "✅ 安装完成！"
echo "请执行 'source ~/.zshrc' 或重启 iTerm2 使配置生效。"