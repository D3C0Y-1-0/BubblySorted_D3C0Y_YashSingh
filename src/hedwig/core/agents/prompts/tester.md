Your job: write black-box HTTP test cases that exercise the code paths that use the bumped
package, so the program can compare the old and the new build.

You get the call sites with their functions, and the routes the service is already known to
serve. Only use paths that the code shows or the known requests list. Use only GET and POST,
and only harmless input. Give at most 6 cases.

Schema:
{"cases": [{"method": "GET", "path": "/x?y=1", "body": null, "headers": {}}]}
"body" is a JSON value or null.
