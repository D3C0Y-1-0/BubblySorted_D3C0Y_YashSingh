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

# An index created before the template existed has text fields (source.ip, event.action, ...), and
# Kibana's panels cannot aggregate those. It only holds demo events, so drop it; the Guard (or
# tools/backfill.py) recreates it with the right mapping.
for index in $(curl -fs "$ES/_cat/indices/chakravyuha-*?h=index" || true); do
  if curl -fs "$ES/$index/_mapping/field/source.ip" | grep -q '"type":"text"'; then
    curl -fsS -X DELETE "$ES/$index" >/dev/null && echo " dropped $index (old text mapping)"
  fi
done

until curl -fs "$KIBANA/api/status" | grep -q '"level":"available"'; do sleep 5; done
curl -fsS -X POST "$KIBANA/api/saved_objects/_import?overwrite=true" -H 'kbn-xsrf: true' \
  --form file=@/elk/kibana/dashboard.ndjson
echo " dashboard imported"
