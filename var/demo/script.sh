#!/bin/bash

. ./util.sh

SOURCE_DIR=$PWD

desc "Let's create a new filter"
desc "We use the WebAssembly Hub CLI tool, wasme"
run "ls -al"

# pushd ./filter > /dev/null 2>&1

desc "Let's open our project"
run "ls -al "

# popd 

# split the screen and run the polling script in bottom script
tmux split-window -v -d -c $SOURCE_DIR
tmux select-pane -t 0
tmux send-keys -t 1 "curl -v http://localhost:8080/posts/1" 

read -s

# wasme deploy
run "ls -al"
