#!/bin/sh
# One-shot: install the index template, then import the Kibana dashboard. Run by the elk-setup
# container in ../docker-compose.yml; safe to run again (both are overwrites).
set -eu
ES=${ES:-http://elasticsearch:9200}
KIBANA=${KIBANA:-http://kibana:5601}

until curl -fs "$ES/_cluster/health?wait_for_status=yellow&timeout=5s" >/dev/null; do sleep 3; done
curl -fsS -X PUT "$ES/_index_template/chakravyuha" -H 'Content-Type: application/json' \
  --data-binary @/elk/index-template.json
echo " template installed"

until curl -fs "$KIBANA/api/status" | grep -q '"level":"available"'; do sleep 5; done
curl -fsS -X POST "$KIBANA/api/saved_objects/_import?overwrite=true" -H 'kbn-xsrf: true' \
  --form file=@/elk/kibana/dashboard.ndjson
echo " dashboard imported"
