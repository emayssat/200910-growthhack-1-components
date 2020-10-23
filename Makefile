DOCKER?= docker
DKR_CONTAINER_NAME?= paasteurizers-spire-dev

DKR_IMAGE_FAMILY_NAME?= paasteurizers/spire-dev
DKR_IMAGE_TAG?= v1
DKR_IMAGE_NAME?= $(DKR_IMAGE_FAMILY_NAME):$(DKR_IMAGE_TAG)

_default_target:
	grep --only-matching --extended-regexp '^[-_a-zA-Z0-9]+:' Makefile

amend:
	git commit -a --amend --no-edit 
	git push --force

#---------------------------------------------------------------------- Container

delete_container: stop_container
	-$(DOCKER) container rm $(DKR_CONTAINER_NAME) 

push_image:
	$(DOCKER) push $(DKR_IMAGE_NAME)

restart_container: stop_container start_container

ssh_container:
	$(DOCKER) exec -it $(DKR_CONTAINER_NAME)  /bin/bash

start_container:
	$(DOCKER) run --detach --rm \
			--name $(DKR_CONTAINER_NAME) \
			--volume $(abspath ./):/root/spire \
			$(DKR_IMAGE_NAME)

stop_container:
	$(DOCKER) stop $(DKR_CONTAINER_NAME)

tail_container:
	$(DOCKER) logs -f $(DKR_CONTAINER_NAME)

view_containers:
	$(DOCKER) ps

#---------------------------------------------------------------------- Image

build_image:
	$(DOCKER) build -t $(DKR_IMAGE_NAME) .

inspect_image:
	$(DOCKER) inspect $(DKR_IMAGE_NAME)

show_image:
	$(DOCKER) image ls | grep $(DKR_IMAGE_NAME)

view_images:
	$(DOCKER) image ls

#----------------------------------------------------------------------
AGENT?= ./bin/spire-agent
SERVER?= ./bin/spire-server
TRUST_DOMAIN?= paasteurizers.iam
TOKEN?= $(shell $(SERVER) token generate -spiffeID spiffe://$(TRUST_DOMAIN)/host | cut -d ' ' -f 2)
start_server:
	$(SERVER) run --config ./etc/server/server.conf &

get_token:
	# This token is a one-time token!
	$(SERVER) token generate -spiffeID spiffe://paasteurizers.iam/host

start_agent:
	$(AGENT) run -config ./etc/agent/agent.conf -joinToken $(TOKEN) &
