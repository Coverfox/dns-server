#!/usr/bin/env bash
if ! pyenv_loc="$(type -p "pyenv")" || [ -z "$pyenv_loc" ]; then
    curl -L https://raw.githubusercontent.com/pyenv/pyenv-installer/master/bin/pyenv-installer | bash
fi

sudo apt-get install -y make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev xz-utils tk-dev

if ! py_3_6_loc="$(type -p "python3.6")" || [ -z "$py_3_6_loc" ]; then
    pyenv install 3.6.4
fi

pyenv virtualenv 3.6.4 dns_server
