.DEFAULT_GOAL := venv-update
.PHONY: venv-update

VIRTUAL_ENV ?= envproj

./requirements.txt: ./requirements.in
	pip-compile

venv-update: $(VIRTUAL_ENV)/.venv.touch

$(VIRTUAL_ENV)/.venv.touch: ./requirements.txt
	./venv-update venv= $(VIRTUAL_ENV) -p`pyenv which python`
	touch $(VIRTUAL_ENV)/.venv.touch
