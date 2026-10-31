# Hedwig Chakravyuha. Everything runs locally on 127.0.0.1; the Guard runs natively (not in a
# container) while the bank and ELK run in Compose. Targets shell out to Python so they also
# work on Windows without make (run the commands they print).
COMPOSE = deploy/docker-compose.yml
UV = uv run --project .

.PHONY: stack guard dashboard test illusion demo-reset up down logs

stack:            ## build and start the bank + ELK (127.0.0.1 only)
	docker compose -f $(COMPOSE) up -d --build

down:             ## stop the stack
	docker compose -f $(COMPOSE) down

guard:            ## run the Guard and dashboard natively (needs the stack up)
	$(UV) chakravyuha

illusion:         ## (re)build the decoy bank content into decoy/bank.json
	$(UV) chakravyuha illusion

test:             ## run the Guard's test suite
	$(UV) pytest tests

demo-reset:       ## empty logs and clear traps/bans/honeytokens; add VERSIONS=1 to restore seeds
	$(UV) python tools/demo_reset.py $(if $(VERSIONS),--versions,)

up: stack guard   ## start the stack, then the Guard
