#!/usr/bin/env bash
set -e

if ! pyenv_loc="$(type -p "pyenv")" || [ -z "$pyenv_loc" ]; then
    curl -L https://raw.githubusercontent.com/pyenv/pyenv-installer/master/bin/pyenv-installer | bash
fi

sudo apt-get install -y make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev xz-utils tk-dev

export PATH="$HOME/.pyenv/bin:$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

pyenv install -s

pyenv virtualenv dns_server
pyenv activate dns_server && pip install virtualenv
