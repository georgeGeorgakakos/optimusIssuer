# optimusIssuer
IMAGE ?= ghcr.io/georgegeorgakakos/optimusissuer
TAG   ?= 1.0.0
NS    ?= optimusissuer

.DEFAULT_GOAL := help

help:  ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	 | awk 'BEGIN {FS=":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

ui:  ## build the single-page application
	cd web && npm ci && npm run build

build: ui  ## build both binaries locally
	go build -o bin/issuerd ./cmd/issuerd
	go build -o bin/issuerctl ./cmd/issuerctl

test:  ## run the Go tests
	go test ./... -count=1

vet:  ## static checks
	go vet ./...

image:  ## build the container image
	docker build -t $(IMAGE):$(TAG) .

push:  ## push the image
	docker push $(IMAGE):$(TAG)

dev:  ## run the service locally with auth disabled
	go run ./cmd/issuerd -key ./dev.key -agent http://localhost:18001 -oidc-issuer=""

dev-ui:  ## run the frontend with hot reload against a local service
	cd web && npm run dev

keygen:  ## create a development key
	go run ./cmd/issuerctl keygen --out ./dev.key --label "development"

deploy:  ## apply the manifests
	kubectl apply -f deploy/01-namespace.yaml
	kubectl apply -f deploy/03-deployment.yaml
	kubectl apply -f deploy/04-ingressroute.yaml
	kubectl apply -f deploy/05-networkpolicy.yaml

logs:  ## tail the service log
	kubectl -n $(NS) logs -f deploy/optimusissuer

clean:  ## remove build output
	rm -rf bin cmd/issuerd/webdist web/node_modules

.PHONY: help ui build test vet image push dev dev-ui keygen deploy logs clean
