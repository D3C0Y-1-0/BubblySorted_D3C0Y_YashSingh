const _ = require("lodash");

// Renders a greeting. The template variable list is built from a config string.
function renderGreeting(name) {
  const compiled = _.template("Hello <%= data.name %>!", { variable: "data, helpers" });
  return compiled({ name });
}

module.exports = { renderGreeting };
