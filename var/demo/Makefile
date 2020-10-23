
cyan := $(shell which tput > /dev/null && tput setaf 6 || echo "")
reset := $(shell which tput > /dev/null && tput sgr0 || echo "")
bold  := $(shell which tput > /dev/null && tput bold || echo "")

help:
	@echo "$(bold)Targets:$(reset)"
	@echo "    $(cyan)setup$(reset)   Prepare the environment"
	@echo "    $(cyan)run$(reset)     Run the scripted demo"
	@echo "    $(cyan)reset$(reset)   Reset the environment"
	

reset:

run:
	tmux new-session -s my_session './script.sh'

setup:
